"""Build a non-authoritative current-facts packet from a validated profile snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from market_aligner.config import ProductPaths, open_existing_private_data_root
from market_aligner.llm.codex_gateway import CodexSemanticGateway
from market_aligner.llm.contracts import LLMReceipt, canonical_hash
from market_aligner.profiler.fact_packet import compile_selected_facts
from market_aligner.profiler.recovery_manifest import select_recovered_input_descriptors
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
_REQUIRED_DESCRIPTOR_KINDS = (
    _PROFILE_DESCRIPTOR_KIND,
    _EVIDENCE_DESCRIPTOR_KIND,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
    ) -> None:
        self._root_chain = None
        self._directories: list[_RetainedDirectory] = []
        self._files: list[tuple[str, int, tuple, bytes, int, str]] = []
        self._manifest_parent_fd: int | None = None
        self.manifest_bytes = b""
        self.files: dict[str, bytes] = {}
        self.descriptors: dict[str, dict[str, object]] = {}
        self.manifest_sha256 = expected_manifest_sha256
        try:
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
