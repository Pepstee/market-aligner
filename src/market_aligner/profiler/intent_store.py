"""Append-only external storage for candidate-intent authority revisions."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import fcntl

from market_aligner.applications.canonical import (
    ContractValidationError,
    canonical_json_bytes,
    digest_bytes,
    parse_canonical_json,
    require_exact_keys,
    require_mapping,
    require_sha256,
    require_timestamp,
)
from market_aligner.config import ProductPaths
from market_aligner.profiler.intent import CandidateIntentDocument
from market_aligner.profiler.schema import validate_profile_id


_MANIFEST_KEYS = {
    "authority_revision",
    "authority_source_sha256",
    "candidate_intent_sha256",
    "profile_id",
    "profile_version",
    "schema_version",
    "valid_until",
}


def _exclusive_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if path.read_bytes() != content:
            raise ContractValidationError("intent authority identity has conflicting bytes")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise ContractValidationError("intent authority raced with conflicting bytes")
    finally:
        temporary_path.unlink(missing_ok=True)


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


@contextmanager
def _current_head_lock(root: Path):
    """Serialize the compare-and-replace projection for one opaque profile."""

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = root / ".current.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@dataclass(frozen=True)
class StoredCandidateIntent:
    document: CandidateIntentDocument
    authority_source_exact_bytes: bytes
    valid_until: str
    current: bool


class CandidateIntentAuthorityStore:
    """Keep authority bytes private, immutable, and selected only by exact digest."""

    def __init__(self, data_home: str | Path | None = None) -> None:
        self.paths = ProductPaths.resolve(data_home).ensure()

    def _root(self, profile_id: str) -> Path:
        return self.paths.profiles / validate_profile_id(profile_id) / "intents"

    def register(
        self,
        document: CandidateIntentDocument,
        authority_source_exact_bytes: bytes,
        *,
        valid_until: str,
    ) -> StoredCandidateIntent:
        if not isinstance(document, CandidateIntentDocument):
            raise TypeError("document must be a CandidateIntentDocument")
        if not isinstance(authority_source_exact_bytes, bytes) or not authority_source_exact_bytes:
            raise TypeError("authority source must be non-empty exact bytes")
        require_timestamp(valid_until, "candidate intent valid_until", strict_profile=True)
        if digest_bytes(authority_source_exact_bytes) != document.authority_source_sha256:
            raise ContractValidationError("candidate intent authority-source digest differs")

        root = self._root(document.profile_id)
        digest = document.candidate_intent_sha256
        manifest = {
            "authority_revision": int(document.value["authority_revision"]),
            "authority_source_sha256": document.authority_source_sha256,
            "candidate_intent_sha256": digest,
            "profile_id": document.profile_id,
            "profile_version": document.profile_version,
            "schema_version": "market-aligner.candidate-intent-authority-manifest.v1",
            "valid_until": valid_until,
        }
        manifest_bytes = canonical_json_bytes(manifest)
        _exclusive_bytes(root / "revisions" / digest / "intent.json", document.exact_bytes)
        _exclusive_bytes(root / "revisions" / digest / "manifest.json", manifest_bytes)
        _exclusive_bytes(
            root / "authority-sources" / f"{document.authority_source_sha256}.bin",
            authority_source_exact_bytes,
        )

        current_path = root / "current.json"
        with _current_head_lock(root):
            if current_path.exists():
                current = require_mapping(
                    parse_canonical_json(current_path.read_bytes()),
                    "current candidate intent",
                )
                require_exact_keys(current, _MANIFEST_KEYS, "current candidate intent")
                current_revision = current["authority_revision"]
                if isinstance(current_revision, bool) or not isinstance(current_revision, int):
                    raise ContractValidationError("current candidate-intent revision is invalid")
                if current_revision > manifest["authority_revision"]:
                    return self.load(document.profile_id, digest)
                if (
                    current_revision == manifest["authority_revision"]
                    and current["candidate_intent_sha256"] != digest
                ):
                    raise ContractValidationError(
                        "candidate-intent authority revision already identifies different bytes"
                    )
            _atomic_bytes(current_path, manifest_bytes)
        return self.load(document.profile_id, digest)

    def load(self, profile_id: str, candidate_intent_sha256: str) -> StoredCandidateIntent:
        validate_profile_id(profile_id)
        require_sha256(candidate_intent_sha256, "candidate_intent_sha256")
        root = self._root(profile_id)
        revision = root / "revisions" / candidate_intent_sha256
        intent_bytes = (revision / "intent.json").read_bytes()
        manifest_bytes = (revision / "manifest.json").read_bytes()
        manifest = require_mapping(
            parse_canonical_json(manifest_bytes), "candidate intent authority manifest"
        )
        require_exact_keys(manifest, _MANIFEST_KEYS, "candidate intent authority manifest")
        if manifest["schema_version"] != "market-aligner.candidate-intent-authority-manifest.v1":
            raise ContractValidationError("unsupported candidate-intent authority manifest")
        require_timestamp(manifest["valid_until"], "candidate intent valid_until", strict_profile=True)
        document = CandidateIntentDocument.parse(intent_bytes)
        if (
            document.profile_id != profile_id
            or document.candidate_intent_sha256 != candidate_intent_sha256
            or manifest["candidate_intent_sha256"] != candidate_intent_sha256
            or manifest["profile_id"] != profile_id
            or manifest["profile_version"] != document.profile_version
            or manifest["authority_revision"] != document.value["authority_revision"]
            or manifest["authority_source_sha256"] != document.authority_source_sha256
        ):
            raise ContractValidationError("candidate-intent authority manifest identity differs")
        source = (
            root
            / "authority-sources"
            / f"{document.authority_source_sha256}.bin"
        ).read_bytes()
        if digest_bytes(source) != document.authority_source_sha256:
            raise ContractValidationError("candidate-intent authority-source bytes differ")
        current = require_mapping(
            parse_canonical_json((root / "current.json").read_bytes()),
            "current candidate intent",
        )
        require_exact_keys(current, _MANIFEST_KEYS, "current candidate intent")
        return StoredCandidateIntent(
            document,
            source,
            str(manifest["valid_until"]),
            current["candidate_intent_sha256"] == candidate_intent_sha256,
        )
