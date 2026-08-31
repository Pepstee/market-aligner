"""Repository-reviewed authority for owned provider-observation captures."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from .evidence_matching import canonical_json
from .provider_observation_capture import exact_clean_head


_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
_POLICY_PATH = _FIXTURE_ROOT / "trusted-greenhouse-success-observations.json"
_CAPTURE_OBJECT_ROOT = _FIXTURE_ROOT / "provider-observation-capture-objects"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_JOB_KEY = re.compile(r"^job_[0-9a-f]{64}$")
_ZERO_INTERACTION = {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0}
MARKET_OBSERVATION_KEY_ID = "market-observation-operator-2026-08-27"
MARKET_OBSERVATION_PUBLIC_DER_SHA256 = (
    "1f852ff70c3e7faf34e75c89e2dca9f067a045927967d069ac2bc544dd0bff1e"
)
_ACCEPTANCE_SCHEMA = "market-aligner.provider-observation-acceptance.v1"
_ACCEPTANCE_RECEIPT_SCHEMA = "market-aligner.provider-observation-acceptance-receipt.v1"
_REQUEST_SCHEMA = "market-aligner.provider-observation-request.v1"
_OPERATION = "one_read_only_observation"
_ALLOWED_METHODS = ["GET"]
_ALLOWED_EVIDENCE = [
    "dom_structure",
    "form_inventory",
    "sanitized_network_metadata",
    "sanitized_screenshot",
]
_ZERO_AUTHORITY_LIMITS = {
    "account": 0,
    "click": 0,
    "cookies": 0,
    "email": 0,
    "fill": 0,
    "identity": 0,
    "login": 0,
    "spending": 0,
    "submit": 0,
    "upload": 0,
    "vault": 0,
}
_IMMUTABLE_LEGACY_COLLECTORS = frozenset(
    {
        (
            "jaa.repository-playwright-route-fixture.v1",
            "8c83eb724153beee0f95c53c109cd588ff4fc5cc",
            "732ecb62f54ea395daf729697dfe8c932686cd4328a54b67ae6843537d7ac907",
        ),
        (
            "jaa.playwright-greenhouse-read-only-observer.v3",
            "8b0868399733a33716c3f37818f58dab8cb204bf",
            "2d8859b69fcba66d2c0767fc8fe24a58f5b3c5ed01a3752280d8c6d00056220f",
        ),
    }
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_document(value: bytes, label: str) -> dict[str, object]:
    def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, item in pairs:
            if key in document:
                raise ValueError(f"{label} contains a duplicate key")
            document[key] = item
        return document

    try:
        document = json.loads(value, object_pairs_hook=closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if not isinstance(document, dict) or value != (
        canonical_json(document) + "\n"
    ).encode("utf-8"):
        raise ValueError(f"{label} is not canonical JSON")
    return document


def _exact_utc(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError(f"{label} must be exact RFC3339 UTC Z")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    return value


def _canonical_greenhouse_target(source_url: object, source_job_id: object) -> str:
    if not isinstance(source_url, str) or not isinstance(source_job_id, str):
        raise ValueError("provider observation target is malformed")
    parsed = urlsplit(source_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname
        not in {
            "boards.greenhouse.io",
            "job-boards.greenhouse.io",
            "job-boards.eu.greenhouse.io",
        }
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", parsed.path) is None
    ):
        raise ValueError(
            "provider observation target is not canonical Greenhouse HTTPS"
        )
    match = re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", parsed.path)
    assert match is not None
    if match.group(1) != source_job_id:
        raise ValueError("provider observation source job ID differs from its URL")
    return source_url


def _owned_directory(
    path: str | Path, *, mode: int, label: str
) -> tuple[Path, tuple[int, int]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        resolved = absolute.resolve(strict=True)
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        resolved != absolute
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise ValueError(f"{label} is unsafe")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"{label} ownership or mode differs")
    return resolved, (metadata.st_dev, metadata.st_ino)


def _external_owned_file(
    path: str | Path, *, mode: int, label: str
) -> tuple[bytes, tuple[int, int, int, int]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent, _ = _owned_directory(absolute.parent, mode=0o700, label=f"{label} parent")
    if absolute.parent != parent:
        raise ValueError(f"{label} parent is unsafe")
    parent_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise ValueError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
        ):
            raise ValueError(f"{label} ownership, mode, or links differ")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > 1_048_576:
                raise ValueError(f"{label} is too large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError(f"{label} changed while reading")
        return b"".join(chunks), identity
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def _verify_external_file_identity(
    path: str | Path,
    identity: tuple[int, int, int, int],
    *,
    mode: int,
    label: str,
) -> None:
    _value, current = _external_owned_file(path, mode=mode, label=label)
    if current != identity:
        raise ValueError(f"{label} identity changed across consumption")


def _verify_directory_identity(
    path: str | Path,
    identity: tuple[int, int],
    *,
    mode: int,
    label: str,
) -> None:
    _path, current = _owned_directory(path, mode=mode, label=label)
    if current != identity:
        raise ValueError(f"{label} identity changed across consumption")


def prepare_provider_observation_consumption_root(archive_root: str | Path) -> str:
    """Create the one canonical private nonce store and return its signed identity."""
    root, root_identity = _owned_directory(
        archive_root, mode=0o700, label="provider observation archive root"
    )
    store = root / "provider-observation-acceptance-consumptions"
    try:
        store.mkdir(mode=0o700)
    except FileExistsError:
        pass
    store, store_identity = _owned_directory(
        store, mode=0o700, label="provider observation acceptance store"
    )
    binding = {
        "schema_version": "market-aligner.provider-observation-replay-domain.v1",
        "root_path": str(root),
        "root_identity": list(root_identity),
        "store_identity": list(store_identity),
    }
    return _sha256(canonical_json(binding).encode("utf-8"))


def provider_observation_request_document(
    *,
    job_key: str,
    source_url: str,
    source_job_id: str,
    timeout_ms: int,
    repository_commit: str,
    repository_tree: str,
    collector_source_sha256: str,
    consumption_root_sha256: str,
) -> dict[str, object]:
    if not _JOB_KEY.fullmatch(job_key):
        raise ValueError("provider observation job key is invalid")
    _canonical_greenhouse_target(source_url, source_job_id)
    if (
        isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not 1 <= timeout_ms <= 65_536
    ):
        raise ValueError("provider observation timeout is outside policy")
    if not _HEX_40.fullmatch(repository_commit) or not _HEX_40.fullmatch(
        repository_tree
    ):
        raise ValueError("provider observation Git identity is invalid")
    if not _HEX_64.fullmatch(collector_source_sha256) or not _HEX_64.fullmatch(
        consumption_root_sha256
    ):
        raise ValueError("provider observation content identity is invalid")
    return {
        "schema_version": _REQUEST_SCHEMA,
        "operation": _OPERATION,
        "job_key": job_key,
        "source_url": source_url,
        "source_job_id": source_job_id,
        "timeout_ms": timeout_ms,
        "repository_commit": repository_commit,
        "repository_tree": repository_tree,
        "collector_source_sha256": collector_source_sha256,
        "consumption_root_sha256": consumption_root_sha256,
        "allowed_http_methods": list(_ALLOWED_METHODS),
        "allowed_evidence": list(_ALLOWED_EVIDENCE),
        "interaction_limits": dict(_ZERO_AUTHORITY_LIMITS),
        "retry_after_indeterminate": False,
    }


def build_provider_observation_acceptance_payload(
    *,
    acceptance_id: str,
    nonce: str,
    not_before: str,
    expires_at: str,
    job_key: str,
    source_url: str,
    source_job_id: str,
    timeout_ms: int,
    repository_commit: str,
    repository_tree: str,
    collector_source_sha256: str,
    consumption_root_sha256: str,
    key_id: str | None = None,
    public_der_sha256: str | None = None,
) -> dict[str, object]:
    """Return the exact canonical bytes an external Ed25519 signer must sign."""
    if not _SAFE_ID.fullmatch(acceptance_id) or not _HEX_64.fullmatch(nonce):
        raise ValueError("provider observation acceptance identity is invalid")
    start = _exact_utc(not_before, "provider observation not-before")
    end = _exact_utc(expires_at, "provider observation expiry")
    if start >= end:
        raise ValueError("provider observation acceptance window is empty")
    if key_id is None:
        key_id = MARKET_OBSERVATION_KEY_ID
    if public_der_sha256 is None:
        public_der_sha256 = MARKET_OBSERVATION_PUBLIC_DER_SHA256
    if (
        key_id != MARKET_OBSERVATION_KEY_ID
        or public_der_sha256 != MARKET_OBSERVATION_PUBLIC_DER_SHA256
    ):
        raise ValueError("provider observation signer identity is not pinned")
    request = provider_observation_request_document(
        job_key=job_key,
        source_url=source_url,
        source_job_id=source_job_id,
        timeout_ms=timeout_ms,
        repository_commit=repository_commit,
        repository_tree=repository_tree,
        collector_source_sha256=collector_source_sha256,
        consumption_root_sha256=consumption_root_sha256,
    )
    return {
        "schema_version": _ACCEPTANCE_SCHEMA,
        "acceptance_id": acceptance_id,
        "nonce": nonce,
        "request_sha256": _sha256(canonical_json(request).encode("utf-8")),
        **{key: value for key, value in request.items() if key != "schema_version"},
        "not_before": start,
        "expires_at": end,
        "key_id": key_id,
        "public_der_sha256": public_der_sha256,
    }


@dataclass(frozen=True)
class ProviderObservationAcceptanceReceipt:
    acceptance_id: str
    nonce: str
    request_sha256: str
    envelope_sha256: str
    signature_sha256: str
    consumption_root_sha256: str
    job_key: str
    source_url: str
    source_job_id: str
    timeout_ms: int
    repository_commit: str
    repository_tree: str
    collector_source_sha256: str
    not_before: str
    expires_at: str
    key_id: str
    public_der_sha256: str
    consumed_at: str
    root_identity: tuple[int, int]
    store_identity: tuple[int, int]
    receipt_sha256: str
    schema_version: str = _ACCEPTANCE_RECEIPT_SCHEMA

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version,
            "acceptance_id": self.acceptance_id,
            "nonce": self.nonce,
            "request_sha256": self.request_sha256,
            "envelope_sha256": self.envelope_sha256,
            "signature_sha256": self.signature_sha256,
            "consumption_root_sha256": self.consumption_root_sha256,
            "job_key": self.job_key,
            "source_url": self.source_url,
            "source_job_id": self.source_job_id,
            "timeout_ms": self.timeout_ms,
            "repository_commit": self.repository_commit,
            "repository_tree": self.repository_tree,
            "collector_source_sha256": self.collector_source_sha256,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "public_der_sha256": self.public_der_sha256,
            "consumed_at": self.consumed_at,
            "root_identity": list(self.root_identity),
            "store_identity": list(self.store_identity),
            "operation": _OPERATION,
            "interaction_limits": dict(_ZERO_AUTHORITY_LIMITS),
            "diagnostic_only": True,
            "identity_authority": False,
            "vault_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }
        if include_hash:
            value["receipt_sha256"] = self.receipt_sha256
        return value


def _parse_acceptance(value: bytes) -> dict[str, object]:
    document = _canonical_document(value, "provider observation acceptance envelope")
    signed_keys = set(
        build_provider_observation_acceptance_payload(
            acceptance_id=str(document.get("acceptance_id", "")),
            nonce=str(document.get("nonce", "")),
            not_before=str(document.get("not_before", "")),
            expires_at=str(document.get("expires_at", "")),
            job_key=str(document.get("job_key", "")),
            source_url=str(document.get("source_url", "")),
            source_job_id=str(document.get("source_job_id", "")),
            timeout_ms=document.get("timeout_ms"),
            repository_commit=str(document.get("repository_commit", "")),
            repository_tree=str(document.get("repository_tree", "")),
            collector_source_sha256=str(document.get("collector_source_sha256", "")),
            consumption_root_sha256=str(document.get("consumption_root_sha256", "")),
            key_id=str(document.get("key_id", "")),
            public_der_sha256=str(document.get("public_der_sha256", "")),
        )
    )
    if set(document) != signed_keys | {"signature_b64", "envelope_sha256"}:
        raise ValueError("provider observation acceptance schema is not closed")
    signed = {key: document[key] for key in signed_keys}
    expected = build_provider_observation_acceptance_payload(
        acceptance_id=str(document["acceptance_id"]),
        nonce=str(document["nonce"]),
        not_before=str(document["not_before"]),
        expires_at=str(document["expires_at"]),
        job_key=str(document["job_key"]),
        source_url=str(document["source_url"]),
        source_job_id=str(document["source_job_id"]),
        timeout_ms=document["timeout_ms"],
        repository_commit=str(document["repository_commit"]),
        repository_tree=str(document["repository_tree"]),
        collector_source_sha256=str(document["collector_source_sha256"]),
        consumption_root_sha256=str(document["consumption_root_sha256"]),
        key_id=str(document["key_id"]),
        public_der_sha256=str(document["public_der_sha256"]),
    )
    if signed != expected:
        raise ValueError("provider observation acceptance is non-canonical")
    signature_b64 = document["signature_b64"]
    if not isinstance(signature_b64, str):
        raise ValueError("provider observation acceptance signature is malformed")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "provider observation acceptance signature is malformed"
        ) from exc
    if (
        len(signature) != 64
        or base64.b64encode(signature).decode("ascii") != signature_b64
    ):
        raise ValueError("provider observation acceptance signature is non-canonical")
    unsigned_envelope = signed | {"signature_b64": signature_b64}
    envelope_sha256 = _sha256(canonical_json(unsigned_envelope).encode("utf-8"))
    if document["envelope_sha256"] != envelope_sha256:
        raise ValueError("provider observation acceptance envelope identity differs")
    return document


def _verify_acceptance_signature(
    document: Mapping[str, object], public_pem: bytes
) -> str:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "provider observation acceptance requires cryptography"
        ) from exc
    try:
        public_key = serialization.load_pem_public_key(public_pem)
    except ValueError as exc:
        raise ValueError("provider observation public key is malformed") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("provider observation public key is not Ed25519")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if _sha256(public_der) != MARKET_OBSERVATION_PUBLIC_DER_SHA256:
        raise ValueError("provider observation public key identity differs")
    signature = base64.b64decode(str(document["signature_b64"]), validate=True)
    signed = {
        key: value
        for key, value in document.items()
        if key not in {"signature_b64", "envelope_sha256"}
    }
    try:
        public_key.verify(signature, canonical_json(signed).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError(
            "provider observation acceptance signature is invalid"
        ) from exc
    return _sha256(signature)


def _receipt_from_document(value: bytes) -> ProviderObservationAcceptanceReceipt:
    document = _canonical_document(value, "provider observation acceptance receipt")
    expected_keys = set(ProviderObservationAcceptanceReceipt.__dataclass_fields__) | {
        "operation",
        "interaction_limits",
        "diagnostic_only",
        "identity_authority",
        "vault_authority",
        "release_authority",
        "submission_authority",
    }
    if set(document) != expected_keys:
        raise ValueError("provider observation acceptance receipt schema is not closed")
    root_identity = document.get("root_identity")
    store_identity = document.get("store_identity")
    if (
        document["schema_version"] != _ACCEPTANCE_RECEIPT_SCHEMA
        or document["operation"] != _OPERATION
        or document["interaction_limits"] != _ZERO_AUTHORITY_LIMITS
        or document["diagnostic_only"] is not True
        or any(
            document[name] is not False
            for name in (
                "identity_authority",
                "vault_authority",
                "release_authority",
                "submission_authority",
            )
        )
        or not isinstance(root_identity, list)
        or not isinstance(store_identity, list)
        or len(root_identity) != 2
        or len(store_identity) != 2
        or any(type(item) is not int or item < 0 for item in root_identity)
        or any(type(item) is not int or item < 0 for item in store_identity)
    ):
        raise ValueError("provider observation acceptance receipt authority differs")
    receipt = ProviderObservationAcceptanceReceipt(
        **{
            key: (
                tuple(document[key])
                if key in {"root_identity", "store_identity"}
                else document[key]
            )
            for key in ProviderObservationAcceptanceReceipt.__dataclass_fields__
        }
    )
    _exact_utc(receipt.not_before, "provider observation receipt not-before")
    _exact_utc(receipt.expires_at, "provider observation receipt expiry")
    _exact_utc(receipt.consumed_at, "provider observation receipt consumption time")
    request = provider_observation_request_document(
        job_key=receipt.job_key,
        source_url=receipt.source_url,
        source_job_id=receipt.source_job_id,
        timeout_ms=receipt.timeout_ms,
        repository_commit=receipt.repository_commit,
        repository_tree=receipt.repository_tree,
        collector_source_sha256=receipt.collector_source_sha256,
        consumption_root_sha256=receipt.consumption_root_sha256,
    )
    if (
        not _SAFE_ID.fullmatch(receipt.acceptance_id)
        or not _HEX_64.fullmatch(receipt.nonce)
        or not all(
            _HEX_64.fullmatch(value)
            for value in (
                receipt.request_sha256,
                receipt.envelope_sha256,
                receipt.signature_sha256,
                receipt.receipt_sha256,
            )
        )
        or receipt.key_id != MARKET_OBSERVATION_KEY_ID
        or receipt.public_der_sha256 != MARKET_OBSERVATION_PUBLIC_DER_SHA256
        or receipt.request_sha256 != _sha256(canonical_json(request).encode("utf-8"))
        or not receipt.not_before <= receipt.consumed_at < receipt.expires_at
        or receipt.document() != document
        or receipt.receipt_sha256
        != _sha256(canonical_json(receipt.document(include_hash=False)).encode("utf-8"))
    ):
        raise ValueError("provider observation acceptance receipt identity differs")
    return receipt


def _load_stored_receipt(store: Path, nonce: str) -> bytes | None:
    store_fd = os.open(
        store,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(store_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("provider observation acceptance store is unsafe")
        try:
            descriptor = os.open(
                f"{nonce}.json",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=store_fd,
            )
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
            ):
                raise ValueError("provider observation acceptance receipt is unsafe")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 65_536):
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ValueError(
                    "provider observation acceptance receipt changed while reading"
                )
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(store_fd)


def _store_receipt(store: Path, nonce: str, value: bytes) -> tuple[bytes, bool]:
    store_fd = os.open(
        store,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(store_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("provider observation acceptance store is unsafe")
        name = f"{nonce}.json"

        def read_existing() -> bytes:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=store_fd,
            )
            try:
                current = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_uid != os.getuid()
                    or stat.S_IMODE(current.st_mode) != 0o600
                    or current.st_nlink != 1
                ):
                    raise ValueError(
                        "provider observation acceptance receipt is unsafe"
                    )
                chunks: list[bytes] = []
                while chunk := os.read(descriptor, 65_536):
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)

        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=store_fd,
            )
        except FileExistsError:
            return read_existing(), False
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError(
                        "provider observation acceptance receipt write stalled"
                    )
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(store_fd)
        stored = read_existing()
        if stored != value:
            raise ValueError(
                "provider observation acceptance receipt publication differs"
            )
        return stored, True
    finally:
        os.close(store_fd)


def verify_and_consume_provider_observation_acceptance(
    *,
    envelope_path: str | Path,
    public_key_path: str | Path,
    archive_root: str | Path,
    job_key: str,
    source_url: str,
    source_job_id: str,
    timeout_ms: int,
    repository_commit: str,
    repository_tree: str,
    collector_source_sha256: str,
    now: str | None = None,
) -> tuple[ProviderObservationAcceptanceReceipt, bool]:
    """Verify before browser import and atomically consume one signed nonce."""
    root, root_identity = _owned_directory(
        archive_root, mode=0o700, label="provider observation archive root"
    )
    store, store_identity = _owned_directory(
        root / "provider-observation-acceptance-consumptions",
        mode=0o700,
        label="provider observation acceptance store",
    )
    root_binding = prepare_provider_observation_consumption_root(root)
    envelope, envelope_identity = _external_owned_file(
        envelope_path, mode=0o600, label="provider observation acceptance envelope"
    )
    public_pem, public_identity = _external_owned_file(
        public_key_path, mode=0o644, label="provider observation public key"
    )
    document = _parse_acceptance(envelope)
    expected_payload = build_provider_observation_acceptance_payload(
        acceptance_id=str(document["acceptance_id"]),
        nonce=str(document["nonce"]),
        not_before=str(document["not_before"]),
        expires_at=str(document["expires_at"]),
        job_key=job_key,
        source_url=source_url,
        source_job_id=source_job_id,
        timeout_ms=timeout_ms,
        repository_commit=repository_commit,
        repository_tree=repository_tree,
        collector_source_sha256=collector_source_sha256,
        consumption_root_sha256=root_binding,
    )
    signed_document = {
        key: value
        for key, value in document.items()
        if key not in {"signature_b64", "envelope_sha256"}
    }
    if signed_document != expected_payload:
        raise ValueError(
            "provider observation acceptance does not bind the exact request"
        )
    signature_sha256 = _verify_acceptance_signature(document, public_pem)
    existing_value = _load_stored_receipt(store, str(document["nonce"]))
    if existing_value is not None:
        existing = _receipt_from_document(existing_value)
        if any(
            getattr(existing, key) != value
            for key, value in {
                "acceptance_id": document["acceptance_id"],
                "nonce": document["nonce"],
                "request_sha256": document["request_sha256"],
                "envelope_sha256": document["envelope_sha256"],
                "signature_sha256": signature_sha256,
                "consumption_root_sha256": root_binding,
                "job_key": job_key,
                "source_url": source_url,
                "source_job_id": source_job_id,
                "timeout_ms": timeout_ms,
                "repository_commit": repository_commit,
                "repository_tree": repository_tree,
                "collector_source_sha256": collector_source_sha256,
                "not_before": document["not_before"],
                "expires_at": document["expires_at"],
                "key_id": MARKET_OBSERVATION_KEY_ID,
                "public_der_sha256": MARKET_OBSERVATION_PUBLIC_DER_SHA256,
                "root_identity": root_identity,
                "store_identity": store_identity,
            }.items()
        ):
            raise ValueError(
                "provider observation acceptance nonce binds different evidence"
            )
        _verify_external_file_identity(
            envelope_path,
            envelope_identity,
            mode=0o600,
            label="provider observation acceptance envelope",
        )
        _verify_external_file_identity(
            public_key_path,
            public_identity,
            mode=0o644,
            label="provider observation public key",
        )
        _verify_directory_identity(
            root,
            root_identity,
            mode=0o700,
            label="provider observation archive root",
        )
        _verify_directory_identity(
            store,
            store_identity,
            mode=0o700,
            label="provider observation acceptance store",
        )
        return existing, False
    current = _exact_utc(
        now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provider observation current time",
    )
    if not str(document["not_before"]) <= current < str(document["expires_at"]):
        raise ValueError(
            "provider observation acceptance is outside its validity window"
        )
    receipt_values = {
        "schema_version": _ACCEPTANCE_RECEIPT_SCHEMA,
        "acceptance_id": document["acceptance_id"],
        "nonce": document["nonce"],
        "request_sha256": document["request_sha256"],
        "envelope_sha256": document["envelope_sha256"],
        "signature_sha256": signature_sha256,
        "consumption_root_sha256": root_binding,
        "job_key": job_key,
        "source_url": source_url,
        "source_job_id": source_job_id,
        "timeout_ms": timeout_ms,
        "repository_commit": repository_commit,
        "repository_tree": repository_tree,
        "collector_source_sha256": collector_source_sha256,
        "not_before": document["not_before"],
        "expires_at": document["expires_at"],
        "key_id": MARKET_OBSERVATION_KEY_ID,
        "public_der_sha256": MARKET_OBSERVATION_PUBLIC_DER_SHA256,
        "consumed_at": current,
        "root_identity": root_identity,
        "store_identity": store_identity,
    }
    provisional = ProviderObservationAcceptanceReceipt(
        **receipt_values,
        receipt_sha256="0" * 64,
    )
    receipt = ProviderObservationAcceptanceReceipt(
        **receipt_values,
        receipt_sha256=_sha256(
            canonical_json(provisional.document(include_hash=False)).encode("utf-8")
        ),
    )
    _verify_external_file_identity(
        envelope_path,
        envelope_identity,
        mode=0o600,
        label="provider observation acceptance envelope",
    )
    _verify_external_file_identity(
        public_key_path,
        public_identity,
        mode=0o644,
        label="provider observation public key",
    )
    stored, created = _store_receipt(
        store,
        str(document["nonce"]),
        (canonical_json(receipt.document()) + "\n").encode("utf-8"),
    )
    resolved = _receipt_from_document(stored)
    if resolved != receipt:
        raise ValueError(
            "provider observation acceptance nonce binds different evidence"
        )
    _verify_external_file_identity(
        envelope_path,
        envelope_identity,
        mode=0o600,
        label="provider observation acceptance envelope",
    )
    _verify_external_file_identity(
        public_key_path,
        public_identity,
        mode=0o644,
        label="provider observation public key",
    )
    _verify_directory_identity(
        root,
        root_identity,
        mode=0o700,
        label="provider observation archive root",
    )
    _verify_directory_identity(
        store,
        store_identity,
        mode=0o700,
        label="provider observation acceptance store",
    )
    return resolved, created


def _repository_prefix(repository_root: str | Path) -> str:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(Path(repository_root).resolve(strict=True)),
            "rev-parse",
            "--show-prefix",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    prefix = completed.stdout.strip()
    if completed.returncode != 0 or (prefix and not prefix.endswith("/")):
        raise ValueError("provider observation repository prefix is invalid")
    return prefix


def _git_show(
    repository_root: str | Path,
    revision: str,
    relative_path: str,
    *,
    allow_legacy_root: bool = False,
) -> bytes:
    relative = Path(relative_path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != relative_path
    ):
        raise ValueError("provider observation source path is unsafe")
    committed_path = f"{_repository_prefix(repository_root)}{relative_path}"
    repository = str(Path(repository_root).resolve(strict=True))

    def read_path(path: str) -> bytes | None:
        completed = subprocess.run(
            ["git", "-C", repository, "show", f"{revision}:{path}"],
            check=False,
            capture_output=True,
        )
        return completed.stdout if completed.returncode == 0 else None

    committed = read_path(committed_path)
    legacy = (
        read_path(relative_path)
        if allow_legacy_root and committed_path != relative_path
        else None
    )
    if committed is not None and legacy is not None and committed != legacy:
        raise ValueError("provider observation authority source path is ambiguous")
    value = committed if committed is not None else legacy
    if value is None:
        raise ValueError("provider observation authority source is absent from Git")
    return value


def _trusted_policy() -> tuple[dict[str, object], bytes, str]:
    value = _POLICY_PATH.read_bytes()
    document = _canonical_document(value, "provider observation trust policy")
    authorities = document.get("authorities")
    if (
        document.get("schema_version") != "jaa.trusted-provider-observations.v2"
        or not isinstance(authorities, list)
        or not authorities
    ):
        raise ValueError("provider observation trust policy is malformed")
    return document, value, _sha256(value)


def _verify_exact_head_policy(repository_root: str | Path, policy_value: bytes) -> str:
    head = exact_clean_head(repository_root)
    committed = _git_show(
        repository_root,
        "HEAD",
        "career_automation/fixtures/trusted-greenhouse-success-observations.json",
    )
    if committed != policy_value:
        raise ValueError("provider observation trust policy differs from exact HEAD")
    return head


@dataclass(frozen=True)
class ProviderObservationAuthorityReceipt:
    authority_id: str
    collector_identity: str
    collector_source_path: str
    collector_source_sha256: str
    collector_repository_commit: str
    scope: str
    observation_sha256: str
    capture_manifest_sha256: str
    trust_policy_sha256: str
    source_url: str
    observed_at: str
    attempt_id: str | None
    vacancy_capture_sha256: str | None
    network_evidence_sha256: str
    schema_version: str = "jaa.provider-observation-authority-receipt.v2"

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "collector_identity": self.collector_identity,
            "collector_source_path": self.collector_source_path,
            "collector_source_sha256": self.collector_source_sha256,
            "collector_repository_commit": self.collector_repository_commit,
            "scope": self.scope,
            "observation_sha256": self.observation_sha256,
            "capture_manifest_sha256": self.capture_manifest_sha256,
            "trust_policy_sha256": self.trust_policy_sha256,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "attempt_id": self.attempt_id,
            "vacancy_capture_sha256": self.vacancy_capture_sha256,
            "network_evidence_sha256": self.network_evidence_sha256,
        }


def _matching_authority(
    policy: Mapping[str, object], *, observation_sha256: str, source_url: str
) -> Mapping[str, object]:
    matches = [
        row
        for row in policy["authorities"]
        if isinstance(row, Mapping)
        and row.get("observation_sha256") == observation_sha256
        and row.get("source_url") == source_url
    ]
    if len(matches) != 1:
        raise ValueError(
            "provider success observation is not a unique repository-trusted authority"
        )
    return matches[0]


def _capture_manifest_bytes(
    authority: Mapping[str, object], *, scope: str, archive_root: str | Path
) -> bytes:
    digest = authority.get("capture_manifest_sha256")
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise ValueError("provider observation capture manifest identity is invalid")
    if scope == "repository_fixture":
        name = authority.get("fixture_manifest")
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("provider observation fixture manifest path is invalid")
        path = _FIXTURE_ROOT / name
    elif scope == "production_capture":
        root = Path(archive_root).resolve(strict=True)
        path = root / "provider-observation-captures" / f"{digest}.json"
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("provider observation capture path must not be a symlink")
    else:
        raise ValueError("trusted provider observation scope is unsupported")
    value = path.read_bytes()
    if _sha256(value) != digest:
        raise ValueError("provider observation capture manifest bytes differ")
    return value


def _artifact_bytes(
    digest: str,
    *,
    scope: str,
    archive_root: str | Path,
    authority: Mapping[str, object],
) -> bytes:
    if not _HEX_64.fullmatch(digest):
        raise ValueError("provider observation capture artifact identity is invalid")
    if scope == "repository_fixture":
        names = authority.get("fixture_artifacts")
        if not isinstance(names, Mapping):
            raise ValueError("provider observation fixture artifact map is missing")
        candidates = [name for name, candidate in names.items() if candidate == digest]
        if len(candidates) != 1 or not isinstance(candidates[0], str):
            raise ValueError(
                "provider observation fixture artifact is not uniquely bound"
            )
        name = candidates[0]
        if Path(name).name != name:
            raise ValueError("provider observation fixture artifact path is invalid")
        path = _CAPTURE_OBJECT_ROOT / name
    else:
        root = Path(archive_root).resolve(strict=True)
        path = root / "objects" / digest[:2] / digest
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("provider observation object path must not be a symlink")
    value = path.read_bytes()
    if _sha256(value) != digest:
        raise ValueError("provider observation capture artifact bytes differ")
    return value


def _verify_capture_manifest(
    authority: Mapping[str, object],
    observation: bytes,
    *,
    scope: str,
    archive_root: str | Path,
    repository_root: str | Path,
) -> Mapping[str, object]:
    value = _capture_manifest_bytes(authority, scope=scope, archive_root=archive_root)
    manifest = _canonical_document(value, "provider observation capture manifest")
    artifacts = manifest.get("artifacts")
    collector_identity = manifest.get("collector_identity")
    source_path = manifest.get("collector_source_path")
    source_digest = manifest.get("collector_source_sha256")
    commit = manifest.get("repository_commit")
    if (
        manifest.get("schema_version") != "jaa.provider-observation-capture.v1"
        or manifest.get("capture_mode")
        != (
            "repository_fixture" if scope == "repository_fixture" else "production_live"
        )
        or manifest.get("provider") != "greenhouse"
        or manifest.get("source_url") != authority.get("source_url")
        or manifest.get("observed_at") != authority.get("observed_at")
        or manifest.get("interaction") != _ZERO_INTERACTION
        or not isinstance(artifacts, Mapping)
        or not isinstance(collector_identity, str)
        or not collector_identity
        or collector_identity != collector_identity.strip()
        or not isinstance(source_path, str)
        or Path(source_path).as_posix() != source_path
        or Path(source_path).is_absolute()
        or ".." in Path(source_path).parts
        or "." in Path(source_path).parts
        or not isinstance(source_digest, str)
        or not _HEX_64.fullmatch(source_digest)
        or not isinstance(commit, str)
        or not _HEX_40.fullmatch(commit)
    ):
        raise ValueError("provider observation capture manifest is malformed")
    required_artifacts = {
        "observation",
        "primary_response",
        "visible_content",
        "network_events",
    }
    if not required_artifacts.issubset(artifacts):
        raise ValueError("provider observation capture artifacts are incomplete")
    if scope == "production_capture" and (
        "screenshot" not in artifacts or len(set(artifacts.values())) != len(artifacts)
    ):
        raise ValueError("production provider capture artifacts are not independent")
    resolved: dict[str, bytes] = {}
    for label, digest in artifacts.items():
        if not isinstance(label, str) or not isinstance(digest, str):
            raise ValueError("provider observation capture artifact is malformed")
        resolved[label] = _artifact_bytes(
            digest,
            scope=scope,
            archive_root=archive_root,
            authority=authority,
        )
    if resolved["observation"] != observation:
        raise ValueError("provider observation differs from capture receipt")
    if scope == "production_capture":
        network = _canonical_document(
            resolved["network_events"], "provider observation network evidence"
        )
        events = network.get("events")
        if (
            network.get("schema_version") != "jaa.provider-observation-network.v1"
            or not isinstance(events, list)
            or not any(
                isinstance(event, Mapping)
                and event.get("method") == "GET"
                and event.get("resource_type") == "document"
                and event.get("status") == 200
                and event.get("url") == authority.get("source_url")
                for event in events
            )
            or not resolved["primary_response"]
            or not resolved["visible_content"]
        ):
            raise ValueError(
                "production provider capture transport evidence is invalid"
            )
    source = _git_show(
        repository_root,
        commit,
        source_path,
        allow_legacy_root=True,
    )
    if _sha256(source) != source_digest:
        raise ValueError("provider observation collector source identity differs")
    current_source = _git_show(repository_root, "HEAD", source_path)
    legacy_identity = (collector_identity, commit, source_digest)
    if current_source != source and legacy_identity not in _IMMUTABLE_LEGACY_COLLECTORS:
        raise ValueError("provider observation collector changed since capture")
    if authority.get("collector_identity") is not None:
        raise ValueError("trust policy must not assert or relabel collector identity")
    return manifest


def verify_provider_observation_authority(
    observation: bytes,
    *,
    source_url: str,
    archive_root: str | Path,
    repository_root: str | Path,
) -> ProviderObservationAuthorityReceipt:
    """Resolve exact bytes only through a reviewed, owned capture receipt."""
    digest = _sha256(observation)
    policy, policy_value, policy_sha256 = _trusted_policy()
    _verify_exact_head_policy(repository_root, policy_value)
    authority = _matching_authority(
        policy,
        observation_sha256=digest,
        source_url=source_url,
    )
    observation_document = _canonical_document(
        observation, "trusted provider success observation"
    )
    request = observation_document.get("request")
    vacancy_match = re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", source_url)
    if (
        observation_document.get("schema_version")
        != "jaa.greenhouse-nonconsequential-canary.v1"
        or observation_document.get("provider") != "greenhouse"
        or observation_document.get("observed_at") != authority.get("observed_at")
        or not isinstance(request, Mapping)
        or request.get("url") != source_url
        or observation_document.get("interaction") != _ZERO_INTERACTION
        or vacancy_match is None
    ):
        raise ValueError("trusted provider observation identity is inconsistent")
    scope = authority.get("scope")
    authority_id = authority.get("authority_id")
    if (
        not isinstance(scope, str)
        or not isinstance(authority_id, str)
        or not authority_id
    ):
        raise ValueError("trusted provider observation authority is malformed")
    manifest = _verify_capture_manifest(
        authority,
        observation,
        scope=scope,
        archive_root=archive_root,
        repository_root=repository_root,
    )
    if manifest.get("vacancy_id") != vacancy_match.group(1):
        raise ValueError("provider observation capture vacancy identity differs")
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, Mapping)
    return ProviderObservationAuthorityReceipt(
        authority_id=authority_id,
        collector_identity=str(manifest["collector_identity"]),
        collector_source_path=str(manifest["collector_source_path"]),
        collector_source_sha256=str(manifest["collector_source_sha256"]),
        collector_repository_commit=str(manifest["repository_commit"]),
        scope=scope,
        observation_sha256=digest,
        capture_manifest_sha256=str(authority["capture_manifest_sha256"]),
        trust_policy_sha256=policy_sha256,
        source_url=source_url,
        observed_at=str(authority["observed_at"]),
        attempt_id=(
            str(authority["attempt_id"]) if authority.get("attempt_id") else None
        ),
        vacancy_capture_sha256=(
            str(authority["vacancy_capture_sha256"])
            if authority.get("vacancy_capture_sha256")
            else None
        ),
        network_evidence_sha256=str(artifacts["network_events"]),
    )


def load_provider_observation_authority(
    *,
    source_url: str,
    archive_root: str | Path,
    repository_root: str | Path,
) -> tuple[bytes, ProviderObservationAuthorityReceipt]:
    """Resolve provider bytes from the trusted policy and owned capture only."""
    policy, policy_value, _ = _trusted_policy()
    _verify_exact_head_policy(repository_root, policy_value)
    matches = [
        row
        for row in policy["authorities"]
        if isinstance(row, Mapping) and row.get("source_url") == source_url
    ]
    if len(matches) != 1:
        raise ValueError("provider source URL lacks one trusted observation authority")
    authority = matches[0]
    scope = authority.get("scope")
    if not isinstance(scope, str):
        raise ValueError("provider observation scope is invalid")
    manifest_value = _capture_manifest_bytes(
        authority, scope=scope, archive_root=archive_root
    )
    manifest = _canonical_document(
        manifest_value, "provider observation capture manifest"
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or not isinstance(
        artifacts.get("observation"), str
    ):
        raise ValueError("provider observation capture lacks observation bytes")
    observation = _artifact_bytes(
        str(artifacts["observation"]),
        scope=scope,
        archive_root=archive_root,
        authority=authority,
    )
    receipt = verify_provider_observation_authority(
        observation,
        source_url=source_url,
        archive_root=archive_root,
        repository_root=repository_root,
    )
    return observation, receipt


__all__ = [
    "MARKET_OBSERVATION_KEY_ID",
    "MARKET_OBSERVATION_PUBLIC_DER_SHA256",
    "ProviderObservationAcceptanceReceipt",
    "ProviderObservationAuthorityReceipt",
    "build_provider_observation_acceptance_payload",
    "load_provider_observation_authority",
    "prepare_provider_observation_consumption_root",
    "provider_observation_request_document",
    "verify_and_consume_provider_observation_acceptance",
    "verify_provider_observation_authority",
]
