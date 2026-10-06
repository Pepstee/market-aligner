"""Build a non-authoritative current-facts packet from a validated profile snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from market_aligner.config import ProductPaths, open_existing_private_data_root
from market_aligner.llm.codex_gateway import (
    CURRENT_FACT_SELECTION_PROMPT_VERSION,
    CodexSemanticGateway,
    PROVIDER_IDENTITY,
)
from market_aligner.llm.contracts import LLMReceipt, LLMTransportReceipt, canonical_hash
from market_aligner.profiler.fact_packet import (
    compile_selected_facts,
    serialize_projection_documents,
    validate_current_profile_projection_receipt,
)
from market_aligner.profiler.recovery_manifest import (
    select_recovered_input_descriptors,
    select_saved_cv_descriptors,
)
from market_aligner.profiler.store import (
    MAX_EVIDENCE_BYTES,
    MAX_PROFILE_BYTES,
    _RetainedDirectory,
    _open_verified_leaf,
    _parse_profile_content,
    _pread_exact_bounded,
    _strict_json_loads,
)
from market_aligner.profiler.schema import validate_profile_id


_PROFILE_DESCRIPTOR_KIND = "candidate_profile_and_job_preferences"
_EVIDENCE_DESCRIPTOR_KIND = "existing_profile_claims_and_provenance"
_INVALID = "current_profile_activation_invalid"
_MAX_RECOVERY_MANIFEST_BYTES = 65_536
_MAX_PROFILE_SELECTION_CONTEXT_BYTES = 16_384
_MAX_CURRENT_ACTIVATION_BYTES = 8_388_608
_MAX_RECOVERED_CV_BYTES = 8_388_608
_REQUIRED_DESCRIPTOR_KINDS = (
    _PROFILE_DESCRIPTOR_KIND,
    _EVIDENCE_DESCRIPTOR_KIND,
)
_CURRENT_ACTIVATION_NAME = re.compile(r"activation-[0-9a-f]{32}\.json\Z")
_CURRENT_PROJECTION_AUTHORITY_NAME = re.compile(
    r"projection-([0-9a-f]{32})-candidate-authority\.json\Z"
)
_CURRENT_POLICY_CANARY_NAME = re.compile(r"candidate-policy-([0-9a-f]{64})\.json\Z")
_INVALID_PROJECTION = "current_profile_projection_invalid"
_CURRENT_INVALIDATING_RELATIONSHIPS = frozenset(
    {"retracts", "corrects", "contradicts", "limits"}
)
_CURRENT_NONINVALIDATING_RELATIONSHIPS = frozenset({"unresolved", "not_applicable"})
_CURRENT_REQUIRED_CORRECTION_KINDS = frozenset(
    {"correction", "retraction", "negative_evidence", "work_history_correction"}
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_document_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError(_INVALID_PROJECTION) from None


def _profile_selection_context(snapshot: Any) -> tuple[dict[str, Any], str]:
    profile_hash = snapshot.hashes.get("profile_sha256")
    profile = snapshot.profile
    restrictions = {
        "blind_spots": profile.blind_spots,
        "unknowns": profile.unknowns,
        "exclusions": profile.exclusions,
    }
    if (
        type(profile_hash) is not str
        or len(profile_hash) != 64
        or any(character not in "0123456789abcdef" for character in profile_hash)
        or type(profile.constraints) is not dict
        or any(
            type(values) not in {tuple, list}
            or any(type(value) is not str for value in values)
            for values in restrictions.values()
        )
    ):
        raise ValueError(_INVALID)
    context = {
        "schema": "market-aligner.current-profile-selection-context.v1",
        "active_profile_sha256": profile_hash,
        "constraints": profile.constraints,
        "blind_spots": list(profile.blind_spots),
        "unknowns": list(profile.unknowns),
        "exclusions": list(profile.exclusions),
    }
    try:
        encoded = json.dumps(
            context,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError(_INVALID) from None
    if len(encoded) > _MAX_PROFILE_SELECTION_CONTEXT_BYTES:
        raise ValueError(_INVALID)
    return context, _sha256(encoded)


class PinnedRecoveryInputs:
    """Nofollow, bounded, retained-descriptor view of approved recovery bytes."""

    def __init__(
        self,
        *,
        data_home: str | Path | None,
        manifest_relative_path: str,
        expected_manifest_sha256: str,
        approval_id: str,
        include_saved_cvs: bool = False,
    ) -> None:
        self._root_chain = None
        self._directories: list[_RetainedDirectory] = []
        self._files: list[tuple[str, int, tuple, bytes, int, str]] = []
        self._manifest_parent_fd: int | None = None
        self.manifest_bytes = b""
        self.files: dict[str, bytes] = {}
        self.descriptors: dict[str, dict[str, object]] = {}
        self.saved_cv_bytes: dict[str, bytes] = {}
        self.saved_cv_descriptors: list[dict[str, object]] = []
        self.manifest_sha256 = expected_manifest_sha256
        try:
            if type(include_saved_cvs) is not bool:
                raise ValueError(_INVALID)
            if (
                type(manifest_relative_path) is not str
                or not manifest_relative_path.startswith("recovered-inputs/")
                or "\\" in manifest_relative_path
                or "//" in manifest_relative_path
                or ":" in manifest_relative_path
            ):
                raise ValueError(_INVALID)
            path_parts = manifest_relative_path.split("/")
            if (
                path_parts[-1] != "recovery-manifest.json"
                or any(part in {"", ".", ".."} for part in path_parts)
            ):
                raise ValueError(_INVALID)
            self._root_chain = open_existing_private_data_root(data_home)
            root_path = ProductPaths.resolve(data_home).root
            parent_fd = self._root_chain.deepest_fd
            for part in path_parts[:-1]:
                directory = _RetainedDirectory(
                    parent_fd=parent_fd,
                    name=part,
                    path_label=f"approved recovery directory {part}",
                    private=True,
                )
                directory.initial_proof()
                self._directories.append(directory)
                parent_fd = directory.fd
            self._manifest_parent_fd = parent_fd
            manifest_data, manifest_identity, manifest_fd = _open_verified_leaf(
                parent_fd, path_parts[-1], _MAX_RECOVERY_MANIFEST_BYTES
            )
            self._files.append(
                (
                    "recovery-manifest.json",
                    manifest_fd,
                    manifest_identity,
                    manifest_data,
                    parent_fd,
                    path_parts[-1],
                )
            )
            descriptors = select_recovered_input_descriptors(
                manifest_data, expected_manifest_sha256, approval_id
            )
            manifest = _strict_json_loads(manifest_data)
            expected_destination = str(root_path.joinpath(*path_parts[:-1]))
            if (
                type(manifest) is not dict
                or manifest.get("destination") != expected_destination
                or any(
                    descriptor["relative_path"] == "recovery-manifest.json"
                    for descriptor in descriptors.values()
                )
            ):
                raise ValueError(_INVALID)
            self.manifest_bytes = manifest_data
            self.descriptors = descriptors
            for kind in _REQUIRED_DESCRIPTOR_KINDS:
                descriptor = descriptors[kind]
                relative_parts = str(descriptor["relative_path"]).split("/")
                assert self._manifest_parent_fd is not None
                parent_fd = self._manifest_parent_fd
                for part in relative_parts[:-1]:
                    directory = _RetainedDirectory(
                        parent_fd=parent_fd,
                        name=part,
                        path_label=f"recovered input directory {part}",
                        private=True,
                    )
                    directory.initial_proof()
                    self._directories.append(directory)
                    parent_fd = directory.fd
                maximum = (
                    MAX_PROFILE_BYTES
                    if kind == _PROFILE_DESCRIPTOR_KIND
                    else MAX_EVIDENCE_BYTES
                )
                data, identity, fd = _open_verified_leaf(
                    parent_fd, relative_parts[-1], maximum
                )
                self._files.append(
                    (
                        kind,
                        fd,
                        identity,
                        data,
                        parent_fd,
                        relative_parts[-1],
                    )
                )
                if (
                    len(data) != descriptor["bytes"]
                    or _sha256(data) != descriptor["sha256"]
                ):
                    raise ValueError(_INVALID)
                self.files[kind] = data
            if include_saved_cvs:
                saved_descriptors = select_saved_cv_descriptors(manifest["files"])
                required_paths = {
                    str(value["relative_path"])
                    for value in descriptors.values()
                }
                for descriptor in saved_descriptors:
                    relative_path = str(descriptor["relative_path"])
                    if relative_path in required_paths:
                        raise ValueError(_INVALID)
                    relative_parts = relative_path.split("/")
                    parent_fd = self._manifest_parent_fd
                    assert parent_fd is not None
                    for part in relative_parts[:-1]:
                        directory = _RetainedDirectory(
                            parent_fd=parent_fd,
                            name=part,
                            path_label="approved saved CV directory",
                            private=True,
                        )
                        directory.initial_proof()
                        self._directories.append(directory)
                        parent_fd = directory.fd
                    data, identity, fd = _open_verified_leaf(
                        parent_fd,
                        relative_parts[-1],
                        _MAX_RECOVERED_CV_BYTES,
                    )
                    self._files.append(
                        (
                            f"saved-cv:{relative_path}",
                            fd,
                            identity,
                            data,
                            parent_fd,
                            relative_parts[-1],
                        )
                    )
                    if (
                        len(data) != descriptor["bytes"]
                        or _sha256(data) != descriptor["sha256"]
                    ):
                        raise ValueError(_INVALID)
                    self.saved_cv_bytes[relative_path] = data
                self.saved_cv_descriptors = saved_descriptors
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self) -> None:
        if self._root_chain is None:
            raise ValueError(_INVALID)
        self._root_chain.revalidate()
        for directory in self._directories:
            directory.revalidate()
        for label, fd, identity, expected, parent_fd, name in self._files:
            actual = _pread_exact_bounded(
                fd,
                maximum=len(expected),
                label=label,
                dir_fd=parent_fd,
                name=name,
                expected_identity=identity,
            )
            if actual != expected:
                raise ValueError(_INVALID)

    def close(self) -> None:
        for _label, fd, _identity, _data, _parent_fd, _name in reversed(self._files):
            try:
                os.close(fd)
            except OSError:
                pass
        self._files.clear()
        for directory in reversed(self._directories):
            directory.close()
        self._directories.clear()
        if self._root_chain is not None:
            self._root_chain.close()
            self._root_chain = None

    def __enter__(self) -> "PinnedRecoveryInputs":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()


class PinnedCurrentActivationArtifact:
    """Retain and revalidate one private activation artifact without following links."""

    def __init__(
        self,
        *,
        data_home: str | Path | None,
        profile_id: str,
        artifact_name: str,
        expected_sha256: str,
    ) -> None:
        self._root_chain = None
        self._directories: list[_RetainedDirectory] = []
        self._fd: int | None = None
        self._identity: tuple | None = None
        self._parent_fd: int | None = None
        self._name: str | None = None
        self.raw_bytes = b""
        self.sha256 = expected_sha256
        self.document: dict[str, Any] = {}
        try:
            validate_profile_id(profile_id)
            if (
                type(artifact_name) is not str
                or _CURRENT_ACTIVATION_NAME.fullmatch(artifact_name) is None
                or type(expected_sha256) is not str
                or len(expected_sha256) != 64
                or any(character not in "0123456789abcdef" for character in expected_sha256)
            ):
                raise ValueError(_INVALID_PROJECTION)
            self._root_chain = open_existing_private_data_root(data_home)
            parent_fd = self._root_chain.deepest_fd
            for name, label in (
                ("outputs", "data_home/outputs"),
                ("current-profile-facts", "current profile fact artifacts"),
                (profile_id, "current profile fact profile directory"),
            ):
                directory = _RetainedDirectory(
                    parent_fd=parent_fd,
                    name=name,
                    path_label=label,
                    private=True,
                )
                directory.initial_proof()
                self._directories.append(directory)
                parent_fd = directory.fd
            self._parent_fd = parent_fd
            self._name = artifact_name
            data, identity, fd = _open_verified_leaf(
                parent_fd, artifact_name, _MAX_CURRENT_ACTIVATION_BYTES
            )
            self._fd = fd
            self._identity = identity
            self.raw_bytes = data
            if _sha256(data) != expected_sha256:
                raise ValueError(_INVALID_PROJECTION)
            document = _strict_json_loads(data)
            if (
                type(document) is not dict
                or _canonical_document_bytes(document) != data
            ):
                raise ValueError(_INVALID_PROJECTION)
            self.document = document
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self) -> None:
        if (
            self._root_chain is None
            or self._fd is None
            or self._identity is None
            or self._parent_fd is None
            or self._name is None
        ):
            raise ValueError(_INVALID_PROJECTION)
        self._root_chain.revalidate()
        for directory in self._directories:
            directory.revalidate()
        current = _pread_exact_bounded(
            self._fd,
            maximum=len(self.raw_bytes),
            label="current activation artifact",
            dir_fd=self._parent_fd,
            name=self._name,
            expected_identity=self._identity,
        )
        if current != self.raw_bytes or _sha256(current) != self.sha256:
            raise ValueError(_INVALID_PROJECTION)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        for directory in reversed(self._directories):
            directory.close()
        self._directories.clear()
        if self._root_chain is not None:
            self._root_chain.close()
            self._root_chain = None

    def __enter__(self) -> "PinnedCurrentActivationArtifact":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()


def _validated_activation_selection(
    selection: object,
    records: list[dict[str, str]],
    source_hashes: dict[str, str],
) -> tuple[bytes, list[dict[str, str]]]:
    if (
        type(selection) is not dict
        or set(selection) != {"selection", "excluded_ids", "correction_assessments"}
        or type(selection["selection"]) is not list
        or type(selection["excluded_ids"]) is not list
        or type(selection["correction_assessments"]) is not list
    ):
        raise ValueError(_INVALID_PROJECTION)
    by_id = {record["evidence_id"]: record for record in records}
    selected_ids = {
        row.get("evidence_id")
        for row in selection["selection"]
        if type(row) is dict and type(row.get("evidence_id")) is str
    }
    excluded_ids = selection["excluded_ids"]
    if (
        len(selected_ids) != len(selection["selection"])
        or any(type(value) is not str for value in excluded_ids)
        or len(set(excluded_ids)) != len(excluded_ids)
        or selected_ids & set(excluded_ids)
        or selected_ids | set(excluded_ids) != set(by_id)
    ):
        raise ValueError(_INVALID_PROJECTION)
    assessed_ids: set[str] = set()
    affected_ids: set[str] = set()
    for assessment in selection["correction_assessments"]:
        if (
            type(assessment) is not dict
            or set(assessment)
            != {"source_evidence_id", "relationship", "affected_evidence_ids"}
        ):
            raise ValueError(_INVALID_PROJECTION)
        source_id = assessment["source_evidence_id"]
        relationship = assessment["relationship"]
        affected = assessment["affected_evidence_ids"]
        if (
            type(source_id) is not str
            or source_id not in by_id
            or source_id in assessed_ids
            or source_id in selected_ids
            or source_id not in excluded_ids
            or type(relationship) is not str
            or relationship
            not in _CURRENT_INVALIDATING_RELATIONSHIPS
            | _CURRENT_NONINVALIDATING_RELATIONSHIPS
            or type(affected) is not list
            or any(type(value) is not str for value in affected)
            or len(set(affected)) != len(affected)
            or any(value not in by_id or value == source_id for value in affected)
            or (
                relationship in _CURRENT_INVALIDATING_RELATIONSHIPS
                and not affected
            )
            or (
                relationship in _CURRENT_NONINVALIDATING_RELATIONSHIPS
                and affected
            )
        ):
            raise ValueError(_INVALID_PROJECTION)
        assessed_ids.add(source_id)
        if relationship in _CURRENT_INVALIDATING_RELATIONSHIPS:
            affected_ids.update(affected)
    required_assessments = {
        record["evidence_id"]
        for record in records
        if record["kind"].strip().casefold()
        in _CURRENT_REQUIRED_CORRECTION_KINDS
    }
    if (
        not required_assessments <= assessed_ids
        or not required_assessments <= set(excluded_ids)
        or selected_ids & affected_ids
    ):
        raise ValueError(_INVALID_PROJECTION)
    try:
        return compile_selected_facts(
            records,
            selection["selection"],
            excluded_ids,
            source_hashes,
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError(_INVALID_PROJECTION) from None


def _validate_current_activation_provider_receipt(
    value: object,
    *,
    records: list[dict[str, str]],
    profile_context: dict[str, Any],
    profile_context_sha256: str,
    selection: dict[str, Any],
) -> None:
    if type(value) is not dict or set(value) != set(LLMReceipt.__dataclass_fields__):
        raise ValueError(_INVALID_PROJECTION)
    transport_value = value.get("transport")
    if (
        type(transport_value) is not dict
        or set(transport_value) != set(LLMTransportReceipt.__dataclass_fields__)
    ):
        raise ValueError(_INVALID_PROJECTION)
    try:
        transport = LLMTransportReceipt(**transport_value)
        receipt_fields = dict(value)
        receipt_fields["transport"] = transport
        receipt = LLMReceipt(**receipt_fields)
        inputs = {
            "schema": "market-aligner.current-profile-fact-selection-input.v4",
            "records": records,
            "required_correction_assessment_source_ids": [
                record["evidence_id"]
                for record in records
                if record["kind"].strip().casefold()
                in _CURRENT_REQUIRED_CORRECTION_KINDS
            ],
            "profile_context": profile_context,
            "profile_context_sha256": profile_context_sha256,
        }
        if (
            receipt.receipt_id != transport.receipt_sha256
            or receipt.task != "current_profile_fact_selection"
            or receipt.prompt_version != CURRENT_FACT_SELECTION_PROMPT_VERSION
            or receipt.model != transport.model_identity
            or transport.provider_identity != PROVIDER_IDENTITY
            or transport.invocation_count != 1
            or receipt.input_sha256 != canonical_hash(inputs)
            or receipt.output_sha256 != canonical_hash(selection)
        ):
            raise ValueError(_INVALID_PROJECTION)
    except (TypeError, ValueError, KeyError):
        raise ValueError(_INVALID_PROJECTION) from None


def compile_current_profile_projection(
    *,
    profile_id: str,
    activation_bytes: bytes,
    expected_activation_sha256: str,
    manifest_bytes: bytes,
    expected_manifest_sha256: str,
    approval_id: str,
    recovered_profile_bytes: bytes,
    recovered_evidence_bytes: bytes,
    snapshot: Any,
) -> dict[str, bytes]:
    """Revalidate a saved activation against its approval and live snapshot."""
    try:
        validate_profile_id(profile_id)
        if (
            type(activation_bytes) is not bytes
            or type(expected_activation_sha256) is not str
            or len(expected_activation_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_activation_sha256)
            or _sha256(activation_bytes) != expected_activation_sha256
        ):
            raise ValueError(_INVALID_PROJECTION)
        document = _strict_json_loads(activation_bytes)
        if (
            type(document) is not dict
            or _canonical_document_bytes(document) != activation_bytes
            or set(document)
            != {
                "schema_version",
                "profile_id",
                "profile_version",
                "approval_id",
                "source_hashes",
                "active_snapshot_hashes",
                "profile_selection_context_sha256",
                "selection",
                "source_spans",
                "packet_bindings",
                "factual_packet",
                "factual_packet_sha256",
                "provider_receipt",
                "application_authority",
                "release_authority",
                "submission_authority",
                "activation_sha256",
            }
        ):
            raise ValueError(_INVALID_PROJECTION)
        unsigned = dict(document)
        observed_activation_sha256 = unsigned.pop("activation_sha256")
        if (
            document["schema_version"]
            != "market-aligner.current-profile-fact-activation.v1"
            or observed_activation_sha256 != canonical_hash(unsigned)
            or document["profile_id"] != profile_id
            or document["approval_id"] != approval_id
            or document["application_authority"] is not False
            or document["release_authority"] is not False
            or document["submission_authority"] is not False
        ):
            raise ValueError(_INVALID_PROJECTION)
        snapshot.revalidate()
        descriptors = select_recovered_input_descriptors(
            manifest_bytes, expected_manifest_sha256, approval_id
        )
        profile_descriptor = descriptors[_PROFILE_DESCRIPTOR_KIND]
        evidence_descriptor = descriptors[_EVIDENCE_DESCRIPTOR_KIND]
        expected_source_hashes = {
            "recovery_manifest": expected_manifest_sha256,
            "profile": profile_descriptor["sha256"],
            "evidence": evidence_descriptor["sha256"],
        }
        if (
            type(recovered_profile_bytes) is not bytes
            or len(recovered_profile_bytes) != profile_descriptor["bytes"]
            or _sha256(recovered_profile_bytes) != profile_descriptor["sha256"]
            or type(recovered_evidence_bytes) is not bytes
            or len(recovered_evidence_bytes) != evidence_descriptor["bytes"]
            or _sha256(recovered_evidence_bytes) != evidence_descriptor["sha256"]
            or document["source_hashes"] != expected_source_hashes
        ):
            raise ValueError(_INVALID_PROJECTION)
        recovered_profile, _recovered_evidence, recovered_ledger = _parse_profile_content(
            profile_id, recovered_profile_bytes, recovered_evidence_bytes
        )
        if (
            recovered_profile != snapshot.profile
            or recovered_ledger != snapshot.evidence_ledger
            or profile_id != snapshot.profile_id
            or document["profile_version"] != snapshot.profile.version
            or document["active_snapshot_hashes"] != snapshot.hashes
        ):
            raise ValueError(_INVALID_PROJECTION)
        records = [
            {
                "evidence_id": item.evidence_id,
                "kind": item.kind,
                "claim": item.claim,
                "status": item.status,
            }
            for item in recovered_ledger
        ]
        spans = _evidence_spans(recovered_evidence_bytes, recovered_ledger)
        profile_context, profile_context_sha256 = _profile_selection_context(snapshot)
        if (
            document["profile_selection_context_sha256"]
            != profile_context_sha256
            or document["source_spans"] != spans
        ):
            raise ValueError(_INVALID_PROJECTION)
        packet_bytes, packet_bindings = _validated_activation_selection(
            document["selection"], records, expected_source_hashes
        )
        packet = json.loads(packet_bytes.decode("utf-8", errors="strict"))
        if (
            document["packet_bindings"] != packet_bindings
            or document["factual_packet"] != packet
            or document["factual_packet_sha256"] != _sha256(packet_bytes)
        ):
            raise ValueError(_INVALID_PROJECTION)
        _validate_current_activation_provider_receipt(
            document["provider_receipt"],
            records=records,
            profile_context=profile_context,
            profile_context_sha256=profile_context_sha256,
            selection=document["selection"],
        )
        snapshot.revalidate()
        return serialize_projection_documents(
            profile_id=profile_id,
            activation_sha256=observed_activation_sha256,
            packet_bytes=packet_bytes,
            bindings=packet_bindings,
            source_hashes=expected_source_hashes,
            profile_sha256=snapshot.hashes["profile_sha256"],
            evidence_ledger_sha256=snapshot.hashes["evidence_ledger_sha256"],
        )
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(_INVALID_PROJECTION) from None
    except ValueError as exc:
        if str(exc) == _INVALID_PROJECTION:
            raise
        raise ValueError(_INVALID_PROJECTION) from None


def write_current_profile_projection_documents(
    *,
    data_home: str | Path | None,
    profile_id: str,
    documents: dict[str, bytes],
) -> dict[str, dict[str, str]]:
    """Write create-only projection siblings beside the activation; receipt last."""
    validate_profile_id(profile_id)
    filenames = {
        "evidence_packet_bytes": "evidence-packet.json",
        "candidate_projection_bytes": "candidate-projection.json",
        "candidate_authority_bytes": "candidate-authority.json",
        "profile_projection_receipt_bytes": "projection-receipt.json",
    }
    if (
        type(documents) is not dict
        or set(documents) != set(filenames)
        or any(
            type(value) is not bytes
            or not value
            or len(value) > _MAX_CURRENT_ACTIVATION_BYTES
            for value in documents.values()
        )
    ):
        raise ValueError(_INVALID_PROJECTION)
    root_chain = open_existing_private_data_root(data_home)
    directories: list[_RetainedDirectory] = []
    output_fd: int | None = None
    projection_id = uuid.uuid4().hex
    try:
        parent_fd = root_chain.deepest_fd
        for name, label in (
            ("outputs", "data_home/outputs"),
            ("current-profile-facts", "current profile fact artifacts"),
            (profile_id, "current profile fact profile directory"),
        ):
            directory = _RetainedDirectory(
                parent_fd=parent_fd,
                name=name,
                path_label=label,
                private=True,
            )
            directory.initial_proof()
            directories.append(directory)
            parent_fd = directory.fd
        output_paths: dict[str, dict[str, str]] = {}
        output_root = ProductPaths.resolve(data_home).outputs
        for document_key in (
            "evidence_packet_bytes",
            "candidate_projection_bytes",
            "candidate_authority_bytes",
            "profile_projection_receipt_bytes",
        ):
            filename = f"projection-{projection_id}-{filenames[document_key]}"
            payload = documents[document_key]
            output_fd = os.open(
                filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directories[-1].fd,
            )
            view = memoryview(payload)
            while view:
                count = os.write(output_fd, view)
                if count <= 0:
                    raise OSError("short write while creating projection document")
                view = view[count:]
            os.fsync(output_fd)
            info = os.fstat(output_fd)
            named = os.stat(
                filename, dir_fd=directories[-1].fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(payload)
                or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ValueError(_INVALID_PROJECTION)
            os.close(output_fd)
            output_fd = None
            output_paths[document_key] = {
                "path": str(output_root / "current-profile-facts" / profile_id / filename),
                "sha256": _sha256(payload),
            }
        root_chain.revalidate()
        for directory in directories:
            directory.revalidate()
        for directory in directories:
            os.fsync(directory.fd)
        return output_paths
    finally:
        if output_fd is not None:
            os.close(output_fd)
        for directory in reversed(directories):
            directory.close()
        root_chain.close()


def read_current_profile_projection_bundle(
    *,
    data_home: str | Path | None,
    profile_id: str,
    candidate_authority_path: str | Path,
    expected_candidate_authority_sha256: str,
    profile_sha256: str,
    evidence_ledger_sha256: str,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Read and validate the immutable siblings selected by the pinned authority."""
    root_chain = None
    directories: list[_RetainedDirectory] = []
    opened_fds: list[int] = []
    try:
        validate_profile_id(profile_id)
        for digest in (
            expected_candidate_authority_sha256,
            profile_sha256,
            evidence_ledger_sha256,
        ):
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError(_INVALID_PROJECTION)
        authority_path = Path(candidate_authority_path)
        expected_directory = (
            ProductPaths.resolve(data_home).outputs
            / "current-profile-facts"
            / profile_id
        )
        if (
            not authority_path.is_absolute()
            or ".." in authority_path.parts
            or authority_path.parent != expected_directory
        ):
            raise ValueError(_INVALID_PROJECTION)
        match = _CURRENT_PROJECTION_AUTHORITY_NAME.fullmatch(authority_path.name)
        if match is None:
            raise ValueError(_INVALID_PROJECTION)
        bundle_id = match.group(1)
        prefix = f"projection-{bundle_id}-"
        filenames = {
            "evidence_packet_bytes": f"{prefix}evidence-packet.json",
            "candidate_projection_bytes": f"{prefix}candidate-projection.json",
            "candidate_authority_bytes": authority_path.name,
            "profile_projection_receipt_bytes": f"{prefix}projection-receipt.json",
        }

        root_chain = open_existing_private_data_root(data_home)
        parent_fd = root_chain.deepest_fd
        for name, label in (
            ("outputs", "data_home/outputs"),
            ("current-profile-facts", "current profile fact artifacts"),
            (profile_id, "current profile fact profile directory"),
        ):
            directory = _RetainedDirectory(
                parent_fd=parent_fd,
                name=name,
                path_label=label,
                private=True,
            )
            directories.append(directory)
            directory.initial_proof()
            parent_fd = directory.fd

        documents: dict[str, bytes] = {}
        for key, filename in filenames.items():
            value, _identity_value, descriptor = _open_verified_leaf(
                directories[-1].fd,
                filename,
                _MAX_CURRENT_ACTIVATION_BYTES,
            )
            opened_fds.append(descriptor)
            documents[key] = value
        if _sha256(documents["candidate_authority_bytes"]) != (
            expected_candidate_authority_sha256
        ):
            raise ValueError(_INVALID_PROJECTION)
        receipt = _strict_json_loads(
            documents["profile_projection_receipt_bytes"]
        )
        if type(receipt) is not dict or type(receipt.get("activation_sha256")) is not str:
            raise ValueError(_INVALID_PROJECTION)
        validate_current_profile_projection_receipt(
            documents["profile_projection_receipt_bytes"],
            profile_id=profile_id,
            activation_sha256=receipt["activation_sha256"],
            evidence_packet_bytes=documents["evidence_packet_bytes"],
            candidate_projection_bytes=documents["candidate_projection_bytes"],
            candidate_authority_bytes=documents["candidate_authority_bytes"],
            profile_sha256=profile_sha256,
            evidence_ledger_sha256=evidence_ledger_sha256,
        )
        root_chain.revalidate()
        for directory in directories:
            directory.revalidate()
        return documents, receipt
    except (KeyError, OSError, TypeError, ValueError, UnicodeDecodeError, RecursionError):
        raise ValueError(_INVALID_PROJECTION) from None
    finally:
        for descriptor in opened_fds:
            os.close(descriptor)
        for directory in reversed(directories):
            directory.close()
        if root_chain is not None:
            root_chain.close()


def _evidence_spans(
    evidence_bytes: bytes, evidence_ledger: list[Any]
) -> dict[str, dict[str, Any]]:
    spans: dict[str, dict[str, Any]] = {}
    offset = 0
    row_index = 0
    for raw_row in evidence_bytes.split(b"\n"):
        if raw_row.strip():
            if row_index >= len(evidence_ledger):
                raise ValueError(_INVALID)
            try:
                parsed = json.loads(raw_row.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError(_INVALID) from None
            item = evidence_ledger[row_index]
            if (
                type(parsed) is not dict
                or parsed.get("evidence_id") != item.evidence_id
                or parsed.get("kind") != item.kind
                or parsed.get("claim") != item.claim
                or parsed.get("status") != item.status
                or item.evidence_id in spans
            ):
                raise ValueError(_INVALID)
            try:
                claim_sha256 = _sha256(item.claim.encode("utf-8"))
            except UnicodeEncodeError:
                raise ValueError(_INVALID) from None
            spans[item.evidence_id] = {
                "start_byte": offset,
                "end_byte": offset + len(raw_row),
                "row_sha256": _sha256(raw_row),
                "claim_sha256": claim_sha256,
                "kind": item.kind,
                "status": item.status,
            }
            row_index += 1
        offset += len(raw_row) + 1
    if row_index != len(evidence_ledger):
        raise ValueError(_INVALID)
    return spans


_CURRENT_CANDIDATE_POLICY_PROFILE_FIELDS = {
    "work_authorisation_uk": str,
    "work_authorisation_uk_requires_sponsorship": bool,
    "residence": str,
    "employment_location_on_hire": str,
    "employment_type_policy": str,
    "employment_type_preference": str,
}


def build_current_candidate_policy_catalog(snapshot: Any) -> dict[str, dict[str, str]]:
    """Bind policy source entries to the retained current profile and ledger bytes."""
    try:
        snapshot.revalidate()
        profile_bytes = snapshot._bytes["profile.yaml"]
        evidence_bytes = snapshot._bytes["evidence.jsonl"]
        constraints = snapshot.profile.constraints
        if (
            type(profile_bytes) is not bytes
            or type(evidence_bytes) is not bytes
            or type(constraints) is not dict
        ):
            raise ValueError(_INVALID)
        profile_sha256 = _sha256(profile_bytes)
        catalog: dict[str, dict[str, str]] = {}
        for field, expected_type in _CURRENT_CANDIDATE_POLICY_PROFILE_FIELDS.items():
            if field not in constraints or constraints[field] is None:
                continue
            value = constraints[field]
            if type(value) is not expected_type or (type(value) is str and not value.strip()):
                raise ValueError(_INVALID)
            try:
                claim = json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                claim.encode("utf-8", errors="strict")
            except (TypeError, ValueError, UnicodeEncodeError):
                raise ValueError(_INVALID) from None
            evidence_id = f"profile-field:constraints.{field}"
            catalog[evidence_id] = {
                "evidence_id": evidence_id,
                "kind": "current_profile_field",
                "status": "explicit",
                "claim": claim,
                "source_ref": f"profile.yaml#/constraints/{field}",
                "content_sha256": profile_sha256,
            }
        spans = _evidence_spans(evidence_bytes, snapshot.evidence_ledger)
        for item in snapshot.evidence_ledger:
            span = spans[item.evidence_id]
            if item.evidence_id in catalog:
                raise ValueError(_INVALID)
            catalog[item.evidence_id] = {
                "evidence_id": item.evidence_id,
                "kind": item.kind,
                "status": item.status,
                "claim": item.claim,
                "source_ref": item.source_ref,
                "content_sha256": span["row_sha256"],
            }
        if not catalog or len(catalog) > 512:
            raise ValueError(_INVALID)
        snapshot.revalidate()
        return catalog
    except (KeyError, TypeError, UnicodeEncodeError, json.JSONDecodeError):
        raise ValueError(_INVALID) from None


def compile_current_profile_activation(
    *,
    profile_id: str,
    manifest_bytes: bytes,
    expected_manifest_sha256: str,
    approval_id: str,
    recovered_profile_bytes: bytes,
    recovered_evidence_bytes: bytes,
    snapshot: Any,
    gateway: CodexSemanticGateway,
) -> dict[str, Any]:
    """Semantically select source IDs and compile their exact source statements.

    The result binds the approved recovery bytes to the existing committed
    ProfileStore snapshot. It carries no intent, application, release, or
    submission authority.
    """
    try:
        snapshot.revalidate()
        descriptors = select_recovered_input_descriptors(
            manifest_bytes, expected_manifest_sha256, approval_id
        )
        profile_descriptor = descriptors[_PROFILE_DESCRIPTOR_KIND]
        evidence_descriptor = descriptors[_EVIDENCE_DESCRIPTOR_KIND]
        if (
            type(recovered_profile_bytes) is not bytes
            or len(recovered_profile_bytes) != profile_descriptor["bytes"]
            or _sha256(recovered_profile_bytes) != profile_descriptor["sha256"]
            or type(recovered_evidence_bytes) is not bytes
            or len(recovered_evidence_bytes) != evidence_descriptor["bytes"]
            or _sha256(recovered_evidence_bytes) != evidence_descriptor["sha256"]
        ):
            raise ValueError(_INVALID)
        recovered_profile, _recovered_evidence, recovered_ledger = _parse_profile_content(
            profile_id, recovered_profile_bytes, recovered_evidence_bytes
        )
        if (
            recovered_profile != snapshot.profile
            or recovered_ledger != snapshot.evidence_ledger
            or profile_id != snapshot.profile_id
        ):
            raise ValueError(_INVALID)
        spans = _evidence_spans(recovered_evidence_bytes, recovered_ledger)
        source_hashes = {
            "recovery_manifest": expected_manifest_sha256,
            "profile": profile_descriptor["sha256"],
            "evidence": evidence_descriptor["sha256"],
        }
        records = [
            {
                "evidence_id": item.evidence_id,
                "kind": item.kind,
                "claim": item.claim,
                "status": item.status,
            }
            for item in recovered_ledger
        ]
        profile_context, profile_context_sha256 = _profile_selection_context(snapshot)
        selection, provider_receipt = gateway.select_current_profile_facts(
            records,
            profile_context=profile_context,
            profile_context_sha256=profile_context_sha256,
        )
        if (
            provider_receipt.transport is None
            or provider_receipt.transport.invocation_count != 1
        ):
            raise ValueError(_INVALID)
        packet_bytes, packet_bindings = compile_selected_facts(
            records,
            selection["selection"],
            selection["excluded_ids"],
            source_hashes,
        )
        selected_ids = {row["evidence_id"] for row in selection["selection"]}
        correction_source_ids = {
            row["source_evidence_id"] for row in selection["correction_assessments"]
        }
        correction_affected_ids = {
            evidence_id
            for row in selection["correction_assessments"]
            for evidence_id in row["affected_evidence_ids"]
        }
        if (
            not selected_ids
            or not selected_ids <= set(spans)
            or not correction_source_ids <= set(spans)
            or not correction_affected_ids <= set(spans)
            or {row["id"] for row in packet_bindings} != selected_ids
        ):
            raise ValueError(_INVALID)
        packet = json.loads(packet_bytes.decode("utf-8", errors="strict"))
        snapshot.revalidate()
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(_INVALID) from None
    document: dict[str, Any] = {
        "schema_version": "market-aligner.current-profile-fact-activation.v1",
        "profile_id": profile_id,
        "profile_version": snapshot.profile.version,
        "approval_id": approval_id,
        "source_hashes": source_hashes,
        "active_snapshot_hashes": dict(snapshot.hashes),
        "profile_selection_context_sha256": profile_context_sha256,
        "selection": selection,
        "source_spans": spans,
        "packet_bindings": packet_bindings,
        "factual_packet": packet,
        "factual_packet_sha256": _sha256(packet_bytes),
        "provider_receipt": asdict(provider_receipt),
        "application_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    document["activation_sha256"] = canonical_hash(document)
    return document


def write_current_activation_artifact(
    *, data_home: str | Path | None, profile_id: str, document: dict[str, Any]
) -> tuple[Path, str]:
    """Create one private activation artifact without replacing prior output."""
    validate_profile_id(profile_id)
    unsigned = dict(document)
    observed_hash = unsigned.pop("activation_sha256", None)
    if observed_hash != canonical_hash(unsigned):
        raise ValueError(_INVALID)
    try:
        payload = (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError(_INVALID) from None
    if len(payload) > 8_388_608:
        raise ValueError(_INVALID)

    root_chain = open_existing_private_data_root(data_home)
    output_root: _RetainedDirectory | None = None
    activation_root: _RetainedDirectory | None = None
    profile_root: _RetainedDirectory | None = None
    output_fd: int | None = None
    try:
        output_root = _RetainedDirectory(
            parent_fd=root_chain.deepest_fd,
            name="outputs",
            path_label="data_home/outputs",
            private=True,
        )
        output_root.initial_proof()
        parent_fd = output_root.fd
        for name, label in (
            ("current-profile-facts", "current profile fact artifacts"),
            (profile_id, "current profile fact profile directory"),
        ):
            created = False
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                created = True
            except FileExistsError:
                pass
            if name == "current-profile-facts":
                activation_root = _RetainedDirectory(
                    parent_fd=parent_fd,
                    name=name,
                    path_label=label,
                    private=True,
                )
                activation_root.initial_proof()
                if created:
                    output_root.recapture()
                    output_root.revalidate()
                parent_fd = activation_root.fd
            else:
                profile_root = _RetainedDirectory(
                    parent_fd=parent_fd,
                    name=name,
                    path_label=label,
                    private=True,
                )
                profile_root.initial_proof()
                if created:
                    activation_root.recapture()
                    activation_root.revalidate()
                parent_fd = profile_root.fd
        artifact_name = f"activation-{uuid.uuid4().hex}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        output_fd = os.open(artifact_name, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(payload)
        while view:
            written = os.write(output_fd, view)
            if written <= 0:
                raise OSError("short write while creating current activation artifact")
            view = view[written:]
        os.fsync(output_fd)
        info = os.fstat(output_fd)
        named = os.stat(artifact_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(payload)
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ValueError(_INVALID)
        profile_root.revalidate()
        activation_root.revalidate()
        output_root.revalidate()
        root_chain.revalidate()
        os.fsync(profile_root.fd)
        path = (
            ProductPaths.resolve(data_home).outputs
            / "current-profile-facts"
            / profile_id
            / artifact_name
        )
        return path, _sha256(payload)
    finally:
        if output_fd is not None:
            os.close(output_fd)
        for directory in (profile_root, activation_root, output_root):
            if directory is not None:
                directory.close()
        root_chain.close()


def _current_policy_canary_name(
    *, profile_id: str, track: str, source_job_key: str, activation_sha256: str
) -> str:
    validate_profile_id(profile_id)
    for value in (track, source_job_key):
        if (
            type(value) is not str
            or not value
            or value != value.strip()
            or len(value) > 256
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ValueError(_INVALID_PROJECTION)
    if (
        type(activation_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", activation_sha256) is None
    ):
        raise ValueError(_INVALID_PROJECTION)
    binding = {
        "activation_sha256": activation_sha256,
        "profile_id": profile_id,
        "source_job_key": source_job_key,
        "track": track,
    }
    return f"candidate-policy-{canonical_hash(binding)}.json"


def _validate_current_policy_canary_identity(
    raw: bytes,
    *,
    profile_id: str,
    track: str,
    source_job_key: str,
    target_job_jurisdiction: str,
    activation_name: str,
    activation_sha256: str,
    activation_file_sha256: str,
    recovery_manifest_sha256: str,
    active_snapshot_hashes: dict[str, str],
) -> None:
    try:
        document = _strict_json_loads(raw)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(_INVALID_PROJECTION) from None
    if (
        type(document) is not dict
        or document.get("schema") != "market-aligner.current-candidate-policy-canary.v1"
        or document.get("profile_id") != profile_id
        or document.get("target_job_key") != source_job_key
        or document.get("target_job_jurisdiction") != target_job_jurisdiction
        or document.get("activation_name") != activation_name
        or document.get("activation_sha256") != activation_sha256
        or document.get("activation_file_sha256") != activation_file_sha256
        or document.get("recovery_manifest_sha256") != recovery_manifest_sha256
        or document.get("active_snapshot_hashes") != active_snapshot_hashes
        or document.get("request_matches_receipt") is not True
    ):
        raise ValueError(_INVALID_PROJECTION)
    request = document.get("request")
    receipt = document.get("receipt")
    if (
        type(request) is not dict
        or request.get("schema") != "market-aligner.candidate-policy-input.v1"
        or request.get("target_job_jurisdiction") != target_job_jurisdiction
        or type(receipt) is not dict
        or type(receipt.get("transport")) is not dict
        or type(receipt["transport"].get("invocation_count")) is not int
        or receipt["transport"].get("invocation_count") != 1
    ):
        raise ValueError(_INVALID_PROJECTION)
    _current_policy_canary_name(
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        activation_sha256=activation_sha256,
    )


def _current_policy_canary_directory(
    data_home: str | Path | None, profile_id: str
) -> tuple[Any, list[_RetainedDirectory]]:
    validate_profile_id(profile_id)
    root_chain = open_existing_private_data_root(data_home)
    directories: list[_RetainedDirectory] = []
    parent_fd = root_chain.deepest_fd
    try:
        for name, label in (
            ("outputs", "data_home/outputs"),
            ("current-profile-facts", "current profile fact artifacts"),
            (profile_id, "current profile fact profile directory"),
        ):
            directory = _RetainedDirectory(
                parent_fd=parent_fd,
                name=name,
                path_label=label,
                private=True,
            )
            directories.append(directory)
            directory.initial_proof()
            parent_fd = directory.fd
        return root_chain, directories
    except BaseException:
        for directory in reversed(directories):
            directory.close()
        root_chain.close()
        raise


def write_current_candidate_policy_canary(
    *,
    data_home: str | Path | None,
    profile_id: str,
    track: str,
    source_job_key: str,
    target_job_jurisdiction: str,
    activation_name: str,
    activation_sha256: str,
    activation_file_sha256: str,
    recovery_manifest_sha256: str,
    active_snapshot_hashes: dict[str, str],
    canary_bytes: bytes,
    expected_sha256: str,
) -> tuple[Path, str]:
    """Persist one already-validated provider result as an immutable private sibling."""
    if (
        type(canary_bytes) is not bytes
        or not canary_bytes
        or len(canary_bytes) > _MAX_CURRENT_ACTIVATION_BYTES
        or type(expected_sha256) is not str
        or _sha256(canary_bytes) != expected_sha256
    ):
        raise ValueError(_INVALID_PROJECTION)
    _validate_current_policy_canary_identity(
        canary_bytes,
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        target_job_jurisdiction=target_job_jurisdiction,
        activation_name=activation_name,
        activation_sha256=activation_sha256,
        activation_file_sha256=activation_file_sha256,
        recovery_manifest_sha256=recovery_manifest_sha256,
        active_snapshot_hashes=active_snapshot_hashes,
    )
    name = _current_policy_canary_name(
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        activation_sha256=activation_sha256,
    )
    root_chain, directories = _current_policy_canary_directory(data_home, profile_id)
    output_fd: int | None = None
    existing_fd: int | None = None
    try:
        profile_directory = directories[-1]
        try:
            output_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=profile_directory.fd,
            )
        except FileExistsError:
            existing, _identity, existing_fd = _open_verified_leaf(
                profile_directory.fd, name, _MAX_CURRENT_ACTIVATION_BYTES
            )
            if existing != canary_bytes:
                raise ValueError(_INVALID_PROJECTION)
        else:
            view = memoryview(canary_bytes)
            while view:
                written = os.write(output_fd, view)
                if written <= 0:
                    raise OSError("short write while creating current policy canary")
                view = view[written:]
            os.fsync(output_fd)
            info = os.fstat(output_fd)
            named = os.stat(name, dir_fd=profile_directory.fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(canary_bytes)
                or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ValueError(_INVALID_PROJECTION)
        root_chain.revalidate()
        for directory in directories:
            directory.revalidate()
        os.fsync(profile_directory.fd)
        path = (
            ProductPaths.resolve(data_home).outputs
            / "current-profile-facts"
            / profile_id
            / name
        )
        return path, expected_sha256
    finally:
        if output_fd is not None:
            os.close(output_fd)
        if existing_fd is not None:
            os.close(existing_fd)
        for directory in reversed(directories):
            directory.close()
        root_chain.close()


def read_current_candidate_policy_canary(
    *,
    data_home: str | Path | None,
    profile_id: str,
    track: str,
    source_job_key: str,
    target_job_jurisdiction: str,
    activation_name: str,
    activation_sha256: str,
    activation_file_sha256: str,
    recovery_manifest_sha256: str,
    active_snapshot_hashes: dict[str, str],
) -> tuple[bytes, str]:
    """Read the exact create-only canary sibling selected by its live binding."""
    name = _current_policy_canary_name(
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        activation_sha256=activation_sha256,
    )
    root_chain, directories = _current_policy_canary_directory(data_home, profile_id)
    descriptor: int | None = None
    try:
        raw, _identity, descriptor = _open_verified_leaf(
            directories[-1].fd, name, _MAX_CURRENT_ACTIVATION_BYTES
        )
        digest = _sha256(raw)
        _validate_current_policy_canary_identity(
            raw,
            profile_id=profile_id,
            track=track,
            source_job_key=source_job_key,
            target_job_jurisdiction=target_job_jurisdiction,
            activation_name=activation_name,
            activation_sha256=activation_sha256,
            activation_file_sha256=activation_file_sha256,
            recovery_manifest_sha256=recovery_manifest_sha256,
            active_snapshot_hashes=active_snapshot_hashes,
        )
        root_chain.revalidate()
        for directory in directories:
            directory.revalidate()
        return raw, digest
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(directories):
            directory.close()
        root_chain.close()


def read_current_candidate_policy_canary_for_activation(
    *,
    data_home: str | Path | None,
    profile_id: str,
    track: str,
    source_job_key: str,
    activation_sha256: str,
) -> tuple[bytes, str]:
    """Read the create-only canary selected by a live activation hash.

    The returned bytes are only a lookup result. Callers must validate the
    activation file and pass the document through native receipt/reference
    admission before consuming its selected policy.
    """
    name = _current_policy_canary_name(
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        activation_sha256=activation_sha256,
    )
    root_chain, directories = _current_policy_canary_directory(data_home, profile_id)
    descriptor: int | None = None
    try:
        raw, _identity, descriptor = _open_verified_leaf(
            directories[-1].fd, name, _MAX_CURRENT_ACTIVATION_BYTES
        )
        try:
            document = _strict_json_loads(raw)
            if type(document) is not dict:
                raise ValueError(_INVALID_PROJECTION)
            _validate_current_policy_canary_identity(
                raw,
                profile_id=profile_id,
                track=track,
                source_job_key=source_job_key,
                target_job_jurisdiction=document.get("target_job_jurisdiction"),
                activation_name=document.get("activation_name"),
                activation_sha256=activation_sha256,
                activation_file_sha256=document.get("activation_file_sha256"),
                recovery_manifest_sha256=document.get("recovery_manifest_sha256"),
                active_snapshot_hashes=document.get("active_snapshot_hashes"),
            )
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError(_INVALID_PROJECTION) from None
        root_chain.revalidate()
        for directory in directories:
            directory.revalidate()
        return raw, _sha256(raw)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(directories):
            directory.close()
        root_chain.close()
