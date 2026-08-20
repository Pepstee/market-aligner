"""Authenticated, caller-independent current-time evidence.

Time is authority-bearing at the review and final-click boundaries.  Callers do
not supply an ``evaluated_at`` value; a configured witness issues exact evidence
for one purpose and subject, and authenticates it against configured trust.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import socket
import stat
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .market_aligner_handoff import (
    HandoffContractError,
    canonical_json_bytes,
    decode_canonical_json,
)


CURRENT_TIME_SCHEMA = "jaa.authenticated-current-time.v1"
EXTERNAL_CURRENT_TIME_SCHEMA = "jaa.external-authenticated-current-time.v1"
EXTERNAL_CURRENT_TIME_REQUEST_SCHEMA = "jaa.external-current-time-request.v1"
INSTALLED_PRODUCTION_TIME_SCHEMA = "jaa.external-production-time-provider.v1"
PRODUCTION_TIME_PROVIDER_ID = "gigabyte-external-current-time-v1"
PRODUCTION_TIME_TRUST_ROOT_ID = "gigabyte-jaa-current-time-root-v1"
PRODUCTION_TIME_WITNESS_IDENTITY_SHA256 = hashlib.sha256(
    b"gigabyte-jaa-external-current-time-witness-v1"
).hexdigest()
_COMPILED_PRODUCTION_TIME_CONFIGURATION_PATH = Path(
    "/etc/gigabyte/majaa/jaa-current-time-v1.json"
)
_COMPILED_PRODUCTION_TIME_SERVICE_SOCKET = Path(
    "/run/gigabyte/majaa/jaa-current-time-v1.sock"
)
PRODUCTION_TIME_CONFIGURATION_PATH = _COMPILED_PRODUCTION_TIME_CONFIGURATION_PATH
PRODUCTION_TIME_SERVICE_SOCKET = _COMPILED_PRODUCTION_TIME_SERVICE_SOCKET
PRODUCTION_TIME_SERVICE_PEER_UID = 0
# Public verifier for the reviewed Gigabyte device-local signer.  The matching
# private key remains outside the repository and behind the UID-0 Unix service.
_COMPILED_PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_B64 = (
    "anUwQGSnIDYYu5Q7vCb8E581X+Iher3dn6y2iy1giKA="
)
PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_B64 = (
    _COMPILED_PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_B64
)
PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_SHA256 = (
    "31b02680db90773e2038e9f53d4f616dcaec5f6f4c07fd2e501a53d07e9e21ea"
)
_PRODUCTION_TIME_CONFIGURATION_PATH = PRODUCTION_TIME_CONFIGURATION_PATH
_PRODUCTION_TIME_SERVICE_SOCKET = PRODUCTION_TIME_SERVICE_SOCKET
_MAX_CONFIGURATION_BYTES = 16_384
_MAX_SERVICE_RESPONSE_BYTES = 16_384
_SERVICE_TIMEOUT_SECONDS = 2.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

_PRODUCTION_TIME_VERIFIER_PUBLIC_KEY = base64.b64decode(
    _COMPILED_PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_B64,
    validate=True,
)
_PRODUCTION_TIME_VERIFIER = Ed25519PublicKey.from_public_bytes(
    _PRODUCTION_TIME_VERIFIER_PUBLIC_KEY
)


def _require_external_service_provisioned(
    provisioned_in_reviewed_build: bool = True,
) -> None:
    if not provisioned_in_reviewed_build:
        raise CurrentTimeWitnessError(
            "time_service_unprovisioned",
            "no deployment-owned Gigabyte current-time signer is provisioned",
        )


class CurrentTimeWitnessError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _system_utc_now() -> datetime:
    """Compatibility clock for synthetic tests; production never calls it."""

    return datetime.now(timezone.utc)


def _external_realtime_now() -> datetime:
    """Local currentness check; production issuance time lives in the service."""

    return datetime.now(timezone.utc)


def _installed_configuration_bytes(path: Path) -> tuple[bytes, os.stat_result]:
    """Read one protected regular file without following a final symlink."""

    if not path.is_absolute():
        raise CurrentTimeWitnessError(
            "time_configuration_path",
            "installed current-time configuration path must be absolute",
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise CurrentTimeWitnessError(
            "time_configuration_missing",
            f"installed current-time configuration is absent at {path}",
        ) from exc
    except OSError as exc:
        raise CurrentTimeWitnessError(
            "time_configuration_unsafe",
            "installed current-time configuration cannot be opened safely",
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CurrentTimeWitnessError(
                "time_configuration_unsafe",
                "installed current-time configuration is not a singly-linked regular file",
            )
        if metadata.st_uid != 0:
            raise CurrentTimeWitnessError(
                "time_configuration_owner",
                "installed current-time configuration must be owned by root",
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CurrentTimeWitnessError(
                "time_configuration_permissions",
                "installed current-time configuration must not be accessible by group or other",
            )
        chunks: list[bytes] = []
        remaining = _MAX_CONFIGURATION_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_CONFIGURATION_BYTES:
            raise CurrentTimeWitnessError(
                "time_configuration_size",
                "installed current-time configuration is too large",
            )
        return raw, metadata
    finally:
        os.close(descriptor)


def _validate_root_owned_directory_chain(
    directory: Path,
    *,
    missing_code: str,
    label: str,
) -> None:
    if not directory.is_absolute():
        raise CurrentTimeWitnessError(
            f"{missing_code.removesuffix('_missing')}_path",
            f"{label} path must be absolute",
        )
    current = Path("/")
    for component in directory.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise CurrentTimeWitnessError(
                missing_code,
                f"{label} parent is absent at {current}",
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise CurrentTimeWitnessError(
                f"{missing_code.removesuffix('_missing')}_permissions",
                f"{label} directory chain is not root-owned and protected at {current}",
            )


@dataclass(frozen=True)
class _InstalledExternalConfiguration:
    configuration_sha256: str
    verifier_public_key: bytes


def _parse_installed_configuration(raw: bytes) -> _InstalledExternalConfiguration:
    try:
        document = decode_canonical_json(
            raw,
            label="installed current-time configuration",
            maximum_bytes=_MAX_CONFIGURATION_BYTES,
        )
    except HandoffContractError as exc:
        raise CurrentTimeWitnessError(
            "time_configuration_malformed",
            "installed current-time configuration is not canonical JSON",
        ) from exc
    expected_keys = {
        "environment",
        "provider_id",
        "schema_version",
        "service_peer_uid",
        "service_socket",
        "trust_root_id",
        "verifier_public_key_b64",
        "witness_identity_sha256",
    }
    if type(document) is not dict or set(document) != expected_keys:
        raise CurrentTimeWitnessError(
            "time_configuration_malformed",
            "installed current-time configuration keys differ",
        )
    expected = {
        "environment": "production",
        "provider_id": PRODUCTION_TIME_PROVIDER_ID,
        "schema_version": INSTALLED_PRODUCTION_TIME_SCHEMA,
        "service_peer_uid": PRODUCTION_TIME_SERVICE_PEER_UID,
        "service_socket": str(_COMPILED_PRODUCTION_TIME_SERVICE_SOCKET),
        "trust_root_id": PRODUCTION_TIME_TRUST_ROOT_ID,
        "verifier_public_key_b64": (
            _COMPILED_PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_B64
        ),
        "witness_identity_sha256": PRODUCTION_TIME_WITNESS_IDENTITY_SHA256,
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise CurrentTimeWitnessError(
            "time_configuration_pins",
            "installed current-time configuration differs from compiled production pins",
        )
    try:
        verifier_public_key = base64.b64decode(
            document["verifier_public_key_b64"],
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise CurrentTimeWitnessError(
            "time_configuration_malformed",
            "installed current-time verifier material is invalid",
        ) from exc
    if (
        verifier_public_key != _PRODUCTION_TIME_VERIFIER_PUBLIC_KEY
        or hashlib.sha256(verifier_public_key).hexdigest()
        != PRODUCTION_TIME_VERIFIER_PUBLIC_KEY_SHA256
    ):
        raise CurrentTimeWitnessError(
            "time_configuration_pins",
            "installed current-time verifier material differs from the compiled pin",
        )
    return _InstalledExternalConfiguration(
        configuration_sha256=hashlib.sha256(raw).hexdigest(),
        verifier_public_key=verifier_public_key,
    )


def _installed_configuration(
    compiled_path: Path = _COMPILED_PRODUCTION_TIME_CONFIGURATION_PATH,
) -> _InstalledExternalConfiguration:
    path = _PRODUCTION_TIME_CONFIGURATION_PATH
    if path != compiled_path:
        raise CurrentTimeWitnessError(
            "time_configuration_path",
            "installed current-time configuration path differs from the compiled pin",
        )
    _validate_root_owned_directory_chain(
        path.parent,
        missing_code="time_configuration_missing",
        label="installed current-time configuration",
    )
    raw, _ = _installed_configuration_bytes(path)
    return _parse_installed_configuration(raw)


@dataclass(frozen=True)
class AuthenticatedTimeEvidence:
    evaluated_at: str
    environment: str
    purpose: str
    subject_sha256: str
    trust_root_id: str
    witness_identity_sha256: str
    receipt_bytes: bytes
    receipt_sha256: str

    def __post_init__(self) -> None:
        if self.environment not in {"production", "synthetic"}:
            raise CurrentTimeWitnessError("time_environment", "time environment is invalid")
        if not _PURPOSE.fullmatch(self.purpose):
            raise CurrentTimeWitnessError("time_purpose", "time purpose is invalid")
        for value, label in (
            (self.subject_sha256, "time subject"),
            (self.witness_identity_sha256, "witness identity"),
            (self.receipt_sha256, "time receipt"),
        ):
            if not _SHA256.fullmatch(value):
                raise CurrentTimeWitnessError("time_digest", f"{label} is invalid")
        if not self.trust_root_id or self.trust_root_id != self.trust_root_id.strip():
            raise CurrentTimeWitnessError("time_trust", "time trust-root ID is invalid")
        if not _TIMESTAMP.fullmatch(self.evaluated_at):
            raise CurrentTimeWitnessError("time_timestamp", "time must be whole-second UTC")
        try:
            parsed = datetime.fromisoformat(self.evaluated_at[:-1] + "+00:00")
        except ValueError as exc:
            raise CurrentTimeWitnessError("time_timestamp", "time is not a real instant") from exc
        if parsed.tzinfo != timezone.utc:
            raise CurrentTimeWitnessError("time_timestamp", "time must be UTC")
        if type(self.receipt_bytes) is not bytes or not self.receipt_bytes:
            raise CurrentTimeWitnessError("time_receipt", "time receipt exact bytes are required")
        if hashlib.sha256(self.receipt_bytes).hexdigest() != self.receipt_sha256:
            raise CurrentTimeWitnessError("time_receipt", "time receipt digest differs")
        document = decode_canonical_json(self.receipt_bytes, label="current-time receipt")
        schema_version = document.get("schema_version") if type(document) is dict else None
        proof_key = (
            "signature_b64"
            if schema_version == EXTERNAL_CURRENT_TIME_SCHEMA
            else "trust_proof_sha256"
        )
        expected_keys = {
            "environment",
            "evaluated_at",
            "nonce_sha256",
            "purpose",
            "schema_version",
            "subject_sha256",
            proof_key,
            "trust_root_id",
            "witness_identity_sha256",
        }
        if type(document) is not dict or set(document) != expected_keys:
            raise CurrentTimeWitnessError("time_receipt", "time receipt keys differ")
        if schema_version not in {CURRENT_TIME_SCHEMA, EXTERNAL_CURRENT_TIME_SCHEMA}:
            raise CurrentTimeWitnessError("time_receipt", "time receipt schema differs")
        expected = {
            "environment": self.environment,
            "evaluated_at": self.evaluated_at,
            "purpose": self.purpose,
            "schema_version": schema_version,
            "subject_sha256": self.subject_sha256,
            "trust_root_id": self.trust_root_id,
            "witness_identity_sha256": self.witness_identity_sha256,
        }
        if any(document.get(key) != value for key, value in expected.items()):
            raise CurrentTimeWitnessError("time_receipt", "time receipt binding differs")
        nonce_sha256 = document.get("nonce_sha256")
        if not isinstance(nonce_sha256, str) or not _SHA256.fullmatch(nonce_sha256):
            raise CurrentTimeWitnessError(
                "time_receipt", "time receipt nonce_sha256 is invalid"
            )
        proof = document.get(proof_key)
        if schema_version == CURRENT_TIME_SCHEMA:
            if not isinstance(proof, str) or not _SHA256.fullmatch(proof):
                raise CurrentTimeWitnessError(
                    "time_receipt", "time receipt trust_proof_sha256 is invalid"
                )
        else:
            try:
                signature = base64.b64decode(proof, validate=True)
            except (TypeError, ValueError, binascii.Error) as exc:
                raise CurrentTimeWitnessError(
                    "time_receipt", "time receipt signature is invalid"
                ) from exc
            if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != proof:
                raise CurrentTimeWitnessError(
                    "time_receipt", "time receipt signature is invalid"
                )

    @property
    def instant(self) -> datetime:
        return datetime.fromisoformat(self.evaluated_at[:-1] + "+00:00")


class CurrentTimeIssuer(Protocol):
    """Untrusted evidence source used behind a separately configured verifier."""

    def issue(self, *, purpose: str, subject_sha256: str) -> AuthenticatedTimeEvidence:
        """Return one signed current-time receipt."""


def _current_instant(clock: Callable[[], datetime]) -> datetime:
    try:
        current = clock()
    except Exception as exc:
        raise CurrentTimeWitnessError("time_clock", "trusted clock is unavailable") from exc
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise CurrentTimeWitnessError("time_clock", "trusted clock must be timezone-aware")
    return current.astimezone(timezone.utc).replace(microsecond=0)


def _time_proof(authentication_key: bytes, document_without_proof: object) -> str:
    return hmac.new(
        authentication_key,
        canonical_json_bytes(document_without_proof),
        hashlib.sha256,
    ).hexdigest()


class HMACCurrentTimeIssuer:
    """Current-time source whose receipts are authenticated by a configured peer.

    The issuer's labels are not trusted merely because it exposes them.  They are
    compared with the independently configured pins held by
    :class:`AuthenticatedCurrentTimeWitness`.
    """

    def __init__(
        self,
        *,
        authentication_key: bytes,
        environment: str,
        trust_root_id: str,
        witness_identity_sha256: str,
        clock: Callable[[], datetime] | None = None,
        nonce_source: Callable[[], bytes] | None = None,
    ) -> None:
        if type(authentication_key) is not bytes or len(authentication_key) < 32:
            raise ValueError("current-time authentication key must contain at least 32 bytes")
        if environment not in {"production", "synthetic"}:
            raise ValueError("current-time issuer environment is invalid")
        if environment == "production":
            raise ValueError(
                "production HMAC time issuance is forbidden; use the external installed service"
            )
        if not trust_root_id or trust_root_id != trust_root_id.strip():
            raise ValueError("current-time issuer trust-root ID is invalid")
        if not _SHA256.fullmatch(witness_identity_sha256):
            raise ValueError("current-time issuer identity is invalid")
        self._authentication_key = authentication_key
        self._environment = environment
        self._trust_root_id = trust_root_id
        self._witness_identity_sha256 = witness_identity_sha256
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._nonce_source = nonce_source or (lambda: secrets.token_bytes(32))
        self._configuration_sha256 = None

    def issue(self, *, purpose: str, subject_sha256: str) -> AuthenticatedTimeEvidence:
        if not _PURPOSE.fullmatch(purpose):
            raise CurrentTimeWitnessError("time_purpose", "time purpose is invalid")
        if not _SHA256.fullmatch(subject_sha256):
            raise CurrentTimeWitnessError("time_subject", "time subject is invalid")
        current = _current_instant(self._clock)
        try:
            nonce_bytes = self._nonce_source()
        except Exception as exc:
            raise CurrentTimeWitnessError("time_nonce", "time nonce is unavailable") from exc
        if type(nonce_bytes) is not bytes or len(nonce_bytes) < 16:
            raise CurrentTimeWitnessError("time_nonce", "time nonce is too short")
        evaluated_at = current.strftime("%Y-%m-%dT%H:%M:%SZ")
        unsigned = {
            "environment": self._environment,
            "evaluated_at": evaluated_at,
            "nonce_sha256": hashlib.sha256(nonce_bytes).hexdigest(),
            "purpose": purpose,
            "schema_version": CURRENT_TIME_SCHEMA,
            "subject_sha256": subject_sha256,
            "trust_root_id": self._trust_root_id,
            "witness_identity_sha256": self._witness_identity_sha256,
        }
        receipt = canonical_json_bytes(
            {
                **unsigned,
                "trust_proof_sha256": _time_proof(self._authentication_key, unsigned),
            }
        )
        return AuthenticatedTimeEvidence(
            evaluated_at=evaluated_at,
            environment=self._environment,
            purpose=purpose,
            subject_sha256=subject_sha256,
            trust_root_id=self._trust_root_id,
            witness_identity_sha256=self._witness_identity_sha256,
            receipt_bytes=receipt,
            receipt_sha256=hashlib.sha256(receipt).hexdigest(),
        )


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise CurrentTimeWitnessError(
                "time_service_response",
                "external current-time service closed an incomplete response",
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_service_socket(path: Path) -> None:
    _validate_root_owned_directory_chain(
        path.parent,
        missing_code="time_service_missing",
        label="external current-time service",
    )
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CurrentTimeWitnessError(
            "time_service_missing",
            f"external current-time service is absent at {path}",
        ) from exc
    except OSError as exc:
        raise CurrentTimeWitnessError(
            "time_service_unsafe",
            "external current-time service path cannot be inspected",
        ) from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CurrentTimeWitnessError(
            "time_service_permissions",
            "external current-time service socket is not root-owned and protected",
        )


def _external_service_response(
    request_bytes: bytes,
    compiled_path: Path = _COMPILED_PRODUCTION_TIME_SERVICE_SOCKET,
) -> bytes:
    path = _PRODUCTION_TIME_SERVICE_SOCKET
    if path != compiled_path:
        raise CurrentTimeWitnessError(
            "time_service_pins",
            "external current-time service path differs from the compiled pin",
        )
    _validate_service_socket(path)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(_SERVICE_TIMEOUT_SECONDS)
            connection.connect(str(path))
            peer_option = getattr(socket, "SO_PEERCRED", None)
            if peer_option is None:
                raise CurrentTimeWitnessError(
                    "time_service_peer",
                    "this host cannot authenticate the external service peer",
                )
            peer = connection.getsockopt(
                socket.SOL_SOCKET,
                peer_option,
                struct.calcsize("3i"),
            )
            _pid, peer_uid, _peer_gid = struct.unpack("3i", peer)
            if peer_uid != PRODUCTION_TIME_SERVICE_PEER_UID:
                raise CurrentTimeWitnessError(
                    "time_service_peer",
                    "external current-time service peer identity differs",
                )
            connection.sendall(struct.pack("!I", len(request_bytes)) + request_bytes)
            response_length = struct.unpack("!I", _receive_exact(connection, 4))[0]
            if response_length < 1 or response_length > _MAX_SERVICE_RESPONSE_BYTES:
                raise CurrentTimeWitnessError(
                    "time_service_response",
                    "external current-time service response length is invalid",
                )
            return _receive_exact(connection, response_length)
    except CurrentTimeWitnessError:
        raise
    except (OSError, TimeoutError) as exc:
        raise CurrentTimeWitnessError(
            "time_service_unavailable",
            "external current-time service request failed",
        ) from exc


class ExternalCurrentTimeIssuer:
    """Challenge/response client; production signing key and clock stay external."""

    def __init__(self, configuration: _InstalledExternalConfiguration) -> None:
        if type(configuration) is not _InstalledExternalConfiguration:
            raise CurrentTimeWitnessError(
                "time_configuration",
                "external current-time issuer requires parsed installed configuration",
            )
        self._configuration_sha256 = configuration.configuration_sha256

    def issue(self, *, purpose: str, subject_sha256: str) -> AuthenticatedTimeEvidence:
        if not _PURPOSE.fullmatch(purpose):
            raise CurrentTimeWitnessError("time_purpose", "time purpose is invalid")
        if not _SHA256.fullmatch(subject_sha256):
            raise CurrentTimeWitnessError("time_subject", "time subject is invalid")
        nonce = secrets.token_bytes(32)
        request = canonical_json_bytes(
            {
                "environment": "production",
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "provider_id": PRODUCTION_TIME_PROVIDER_ID,
                "purpose": purpose,
                "schema_version": EXTERNAL_CURRENT_TIME_REQUEST_SCHEMA,
                "subject_sha256": subject_sha256,
                "trust_root_id": PRODUCTION_TIME_TRUST_ROOT_ID,
                "witness_identity_sha256": PRODUCTION_TIME_WITNESS_IDENTITY_SHA256,
            }
        )
        receipt = _external_service_response(request)
        try:
            document = decode_canonical_json(
                receipt,
                label="external current-time response",
                maximum_bytes=_MAX_SERVICE_RESPONSE_BYTES,
            )
            evidence = AuthenticatedTimeEvidence(
                evaluated_at=document["evaluated_at"],
                environment=document["environment"],
                purpose=document["purpose"],
                subject_sha256=document["subject_sha256"],
                trust_root_id=document["trust_root_id"],
                witness_identity_sha256=document["witness_identity_sha256"],
                receipt_bytes=receipt,
                receipt_sha256=hashlib.sha256(receipt).hexdigest(),
            )
        except (HandoffContractError, KeyError, TypeError) as exc:
            raise CurrentTimeWitnessError(
                "time_service_response",
                "external current-time service response is malformed",
            ) from exc
        if (
            document.get("schema_version") != EXTERNAL_CURRENT_TIME_SCHEMA
            or document.get("nonce_sha256") != hashlib.sha256(nonce).hexdigest()
            or evidence.environment != "production"
            or evidence.purpose != purpose
            or evidence.subject_sha256 != subject_sha256
            or evidence.trust_root_id != PRODUCTION_TIME_TRUST_ROOT_ID
            or evidence.witness_identity_sha256
            != PRODUCTION_TIME_WITNESS_IDENTITY_SHA256
        ):
            raise CurrentTimeWitnessError(
                "time_substitution",
                "external current-time response differs from the exact challenge",
            )
        return evidence


def _verify_external_signature(
    document: dict[str, object],
    verifier: Ed25519PublicKey = _PRODUCTION_TIME_VERIFIER,
) -> None:
    unsigned = dict(document)
    encoded = unsigned.pop("signature_b64", None)
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise CurrentTimeWitnessError(
            "time_authentication", "external current-time signature is invalid"
        ) from exc
    try:
        verifier.verify(signature, canonical_json_bytes(unsigned))
    except InvalidSignature as exc:
        raise CurrentTimeWitnessError(
            "time_authentication",
            "external current-time signature is not trusted",
        ) from exc


class AuthenticatedCurrentTimeWitness:
    """Configured verifier with pins independent from the issuer's receipt.

    Arbitrary objects that merely implement ``issue``/``authenticate`` are not
    accepted by :func:`obtain_current_time`.  This closes the former no-op
    authenticator seam while retaining an injectable issuer for negative tests.
    """

    def __init__(
        self,
        issuer: CurrentTimeIssuer,
        *,
        authentication_key: bytes,
        environment: str,
        trust_root_id: str,
        witness_identity_sha256: str,
        trusted_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(authentication_key) is not bytes or len(authentication_key) < 32:
            raise ValueError("current-time authentication key must contain at least 32 bytes")
        if environment not in {"production", "synthetic"}:
            raise ValueError("configured current-time environment is invalid")
        if environment == "production":
            raise ValueError(
                "production HMAC time verification is forbidden; use the external installed service"
            )
        if not trust_root_id or trust_root_id != trust_root_id.strip():
            raise ValueError("configured current-time trust-root ID is invalid")
        if not _SHA256.fullmatch(witness_identity_sha256):
            raise ValueError("configured current-time witness identity is invalid")
        if not callable(getattr(issuer, "issue", None)):
            raise ValueError("configured current-time issuer is invalid")
        self._issuer = issuer
        self._authentication_key = authentication_key
        self._verification_mode = "hmac_synthetic"
        self.environment = environment
        self.trust_root_id = trust_root_id
        self.witness_identity_sha256 = witness_identity_sha256
        self._trusted_clock = trusted_clock or (lambda: datetime.now(timezone.utc))
        self._configuration_sha256 = None
        self._consumed_receipts: set[str] = set()
        self._lock = threading.Lock()
        self.issue_count = 0
        self.authentication_calls: list[tuple[str, str, int]] = []

    def issue(self, *, purpose: str, subject_sha256: str) -> AuthenticatedTimeEvidence:
        evidence = self._issuer.issue(purpose=purpose, subject_sha256=subject_sha256)
        self.issue_count += 1
        return evidence

    def _verify_receipt_proof(self, document: dict[str, object]) -> None:
        if self.environment == "production":
            if (
                self._verification_mode != "external_ed25519"
                or document.get("schema_version") != EXTERNAL_CURRENT_TIME_SCHEMA
            ):
                raise CurrentTimeWitnessError(
                    "time_authentication",
                    "production current-time evidence must come from the external signer",
                )
            _verify_external_signature(document)
            return
        if (
            self._verification_mode != "hmac_synthetic"
            or document.get("schema_version") != CURRENT_TIME_SCHEMA
        ):
            raise CurrentTimeWitnessError(
                "time_authentication", "synthetic current-time proof mode differs"
            )
        unsigned = dict(document)
        supplied_proof = unsigned.pop("trust_proof_sha256", None)
        if not isinstance(supplied_proof, str) or not _SHA256.fullmatch(supplied_proof):
            raise CurrentTimeWitnessError("time_authentication", "time proof is invalid")
        expected_proof = _time_proof(self._authentication_key, unsigned)
        if not hmac.compare_digest(supplied_proof, expected_proof):
            raise CurrentTimeWitnessError("time_authentication", "time proof is not trusted")

    def authenticate(
        self,
        evidence: AuthenticatedTimeEvidence,
        *,
        purpose: str,
        subject_sha256: str,
        maximum_clock_skew_seconds: int,
    ) -> None:
        self.authentication_calls.append(
            (purpose, subject_sha256, maximum_clock_skew_seconds)
        )
        document = decode_canonical_json(evidence.receipt_bytes, label="current-time receipt")
        if type(document) is not dict:
            raise CurrentTimeWitnessError("time_receipt", "time receipt must be an object")
        AuthenticatedCurrentTimeWitness._verify_receipt_proof(self, document)
        if (
            evidence.environment != self.environment
            or evidence.trust_root_id != self.trust_root_id
            or evidence.witness_identity_sha256 != self.witness_identity_sha256
        ):
            raise CurrentTimeWitnessError("time_substitution", "time trust binding differs")
        if evidence.purpose != purpose or evidence.subject_sha256 != subject_sha256:
            raise CurrentTimeWitnessError("time_substitution", "time purpose or subject differs")
        trusted_now = _current_instant(self._trusted_clock)
        delta = (evidence.instant - trusted_now).total_seconds()
        if abs(delta) > maximum_clock_skew_seconds:
            if delta > 0:
                code = "time_future"
            elif abs(delta) > maximum_clock_skew_seconds * 2:
                code = "time_backdated"
            else:
                code = "time_stale"
            raise CurrentTimeWitnessError(code, "time is outside the configured currentness window")
        with self._lock:
            if evidence.receipt_sha256 in self._consumed_receipts:
                raise CurrentTimeWitnessError("time_replay", "time receipt was already consumed")
            self._consumed_receipts.add(evidence.receipt_sha256)

    def assert_consumed(
        self,
        evidence: AuthenticatedTimeEvidence,
        *,
        purpose: str,
        subject_sha256: str,
        maximum_clock_skew_seconds: int,
    ) -> None:
        """Revalidate exact evidence already authenticated by this witness.

        Atomic consumers use this after :func:`obtain_current_time` so they do
        not accept a caller-constructed evidence object or a post-auth mutation.
        It does not consume the receipt a second time.
        """

        validate_current_time_witness_configuration(
            self,
            environment=self.environment,
        )
        if type(evidence) is not AuthenticatedTimeEvidence:
            raise CurrentTimeWitnessError("time_contract", "time evidence type differs")
        try:
            rebuilt = AuthenticatedTimeEvidence(
                evaluated_at=evidence.evaluated_at,
                environment=evidence.environment,
                purpose=evidence.purpose,
                subject_sha256=evidence.subject_sha256,
                trust_root_id=evidence.trust_root_id,
                witness_identity_sha256=evidence.witness_identity_sha256,
                receipt_bytes=evidence.receipt_bytes,
                receipt_sha256=evidence.receipt_sha256,
            )
        except (AttributeError, CurrentTimeWitnessError) as exc:
            raise CurrentTimeWitnessError(
                "time_contract", "time evidence failed invariant reconstruction"
            ) from exc
        document = decode_canonical_json(
            rebuilt.receipt_bytes,
            label="current-time receipt",
        )
        if type(document) is not dict:
            raise CurrentTimeWitnessError(
                "time_receipt", "time receipt must be an object"
            )
        AuthenticatedCurrentTimeWitness._verify_receipt_proof(self, document)
        if (
            rebuilt.environment != self.environment
            or rebuilt.trust_root_id != self.trust_root_id
            or rebuilt.witness_identity_sha256 != self.witness_identity_sha256
            or rebuilt.purpose != purpose
            or rebuilt.subject_sha256 != subject_sha256
        ):
            raise CurrentTimeWitnessError(
                "time_substitution", "time trust, purpose or subject binding differs"
            )
        trusted_now = _current_instant(self._trusted_clock)
        if abs((rebuilt.instant - trusted_now).total_seconds()) > maximum_clock_skew_seconds:
            raise CurrentTimeWitnessError(
                "time_stale", "time is outside the configured currentness window"
            )
        with self._lock:
            if rebuilt.receipt_sha256 not in self._consumed_receipts:
                raise CurrentTimeWitnessError(
                    "time_unconsumed", "time evidence was not authenticated by this witness"
                )


def synthetic_hmac_current_time_witness_for_test(
    *,
    authentication_key: bytes,
    environment: str,
    trust_root_id: str,
    witness_identity_sha256: str,
    clock: Callable[[], datetime] | None = None,
    nonce_source: Callable[[], bytes] | None = None,
) -> AuthenticatedCurrentTimeWitness:
    """Build an injectable synthetic source/verifier pair for tests and fixtures."""

    if environment != "synthetic":
        raise CurrentTimeWitnessError(
            "time_configuration",
            "caller-composed HMAC current-time witnesses are synthetic/test-only",
        )

    source = HMACCurrentTimeIssuer(
        authentication_key=authentication_key,
        environment=environment,
        trust_root_id=trust_root_id,
        witness_identity_sha256=witness_identity_sha256,
        clock=clock,
        nonce_source=nonce_source,
    )
    return AuthenticatedCurrentTimeWitness(
        source,
        authentication_key=authentication_key,
        environment=environment,
        trust_root_id=trust_root_id,
        witness_identity_sha256=witness_identity_sha256,
        trusted_clock=clock,
    )


def installed_production_current_time_witness() -> AuthenticatedCurrentTimeWitness:
    """Load the external deployment-owned production-time verifier/client.

    JAA receives only a pinned Ed25519 public key.  The signing key and issuance
    clock remain behind a root-owned Unix peer at a compiled path.  The
    application call site supplies no key, pin, environment, path or clock.
    """

    configuration = _installed_configuration()
    _require_external_service_provisioned()
    issuer = ExternalCurrentTimeIssuer(configuration)
    witness = object.__new__(AuthenticatedCurrentTimeWitness)
    witness._issuer = issuer
    witness._authentication_key = None
    witness._verification_mode = "external_ed25519"
    witness.environment = "production"
    witness.trust_root_id = PRODUCTION_TIME_TRUST_ROOT_ID
    witness.witness_identity_sha256 = PRODUCTION_TIME_WITNESS_IDENTITY_SHA256
    witness._trusted_clock = _external_realtime_now
    witness._configuration_sha256 = configuration.configuration_sha256
    witness._consumed_receipts = set()
    witness._lock = threading.Lock()
    witness.issue_count = 0
    witness.authentication_calls = []
    return witness


def validate_current_time_witness_configuration(
    witness: AuthenticatedCurrentTimeWitness,
    *,
    environment: str,
) -> None:
    """Require synthetic test trust or the fixed external production verifier."""

    if type(witness) is not AuthenticatedCurrentTimeWitness:
        raise CurrentTimeWitnessError(
            "time_witness",
            "a concrete independently configured current-time verifier is required",
        )
    if environment not in {"production", "synthetic"} or witness.environment != environment:
        raise CurrentTimeWitnessError(
            "time_environment",
            "configured current-time environment differs",
        )
    if environment == "production":
        _require_external_service_provisioned()
        issuer = getattr(witness, "_issuer", None)
        configuration_sha256 = getattr(witness, "_configuration_sha256", None)
        configuration = _installed_configuration()
        if (
            getattr(witness, "_verification_mode", None) != "external_ed25519"
            or type(issuer) is not ExternalCurrentTimeIssuer
            or getattr(issuer, "_configuration_sha256", None) != configuration_sha256
            or not isinstance(configuration_sha256, str)
            or not _SHA256.fullmatch(configuration_sha256)
            or configuration.configuration_sha256 != configuration_sha256
            or configuration.verifier_public_key
            != _PRODUCTION_TIME_VERIFIER_PUBLIC_KEY
            or getattr(witness, "_authentication_key", object()) is not None
            or getattr(witness, "_trusted_clock", None) is not _external_realtime_now
            or witness.trust_root_id != PRODUCTION_TIME_TRUST_ROOT_ID
            or witness.witness_identity_sha256
            != PRODUCTION_TIME_WITNESS_IDENTITY_SHA256
        ):
            raise CurrentTimeWitnessError(
                "time_configuration",
                "production current-time trust differs from the installed external verifier",
            )
    elif (
        getattr(witness, "_verification_mode", None) != "hmac_synthetic"
        or getattr(witness, "_configuration_sha256", None) is not None
        or not callable(getattr(getattr(witness, "_issuer", None), "issue", None))
        or type(getattr(witness, "_authentication_key", None)) is not bytes
    ):
        raise CurrentTimeWitnessError(
            "time_configuration",
            "synthetic current-time trust differs from the test-only HMAC verifier",
        )


def configured_hmac_current_time_witness(
    *,
    authentication_key: bytes,
    environment: str,
    trust_root_id: str,
    witness_identity_sha256: str,
    clock: Callable[[], datetime] | None = None,
    nonce_source: Callable[[], bytes] | None = None,
) -> AuthenticatedCurrentTimeWitness:
    """Compatibility spelling for the explicitly synthetic test factory.

    It intentionally cannot compose production trust.  Production uses the
    separately installed external challenge/response service and never this
    caller-keyed compatibility factory.
    """

    return synthetic_hmac_current_time_witness_for_test(
        authentication_key=authentication_key,
        environment=environment,
        trust_root_id=trust_root_id,
        witness_identity_sha256=witness_identity_sha256,
        clock=clock,
        nonce_source=nonce_source,
    )


def obtain_current_time(
    witness: AuthenticatedCurrentTimeWitness,
    *,
    environment: str,
    purpose: str,
    subject_sha256: str,
    maximum_clock_skew_seconds: int,
) -> AuthenticatedTimeEvidence:
    """Obtain and authenticate one exact current-time witness response."""

    if type(maximum_clock_skew_seconds) is not int or maximum_clock_skew_seconds < 0:
        raise CurrentTimeWitnessError("time_skew", "maximum clock skew is invalid")
    validate_current_time_witness_configuration(witness, environment=environment)
    identity = getattr(witness, "witness_identity_sha256", None)
    if not isinstance(identity, str) or not _SHA256.fullmatch(identity):
        raise CurrentTimeWitnessError("time_witness", "configured witness identity is invalid")
    trust_root_id = getattr(witness, "trust_root_id", None)
    if not isinstance(trust_root_id, str) or not trust_root_id.strip():
        raise CurrentTimeWitnessError("time_witness", "configured witness trust root is invalid")
    try:
        evidence = witness.issue(purpose=purpose, subject_sha256=subject_sha256)
    except CurrentTimeWitnessError:
        raise
    except Exception as exc:
        raise CurrentTimeWitnessError("time_issue", "current-time witness could not issue evidence") from exc
    if not isinstance(evidence, AuthenticatedTimeEvidence):
        raise CurrentTimeWitnessError("time_contract", "current-time witness returned the wrong type")
    if (
        evidence.environment != environment
        or evidence.purpose != purpose
        or evidence.subject_sha256 != subject_sha256
        or evidence.trust_root_id != trust_root_id
        or evidence.witness_identity_sha256 != identity
    ):
        raise CurrentTimeWitnessError("time_substitution", "current-time witness response differs")
    try:
        AuthenticatedCurrentTimeWitness.authenticate(
            witness,
            evidence,
            purpose=purpose,
            subject_sha256=subject_sha256,
            maximum_clock_skew_seconds=maximum_clock_skew_seconds,
        )
    except CurrentTimeWitnessError:
        raise
    except Exception as exc:
        raise CurrentTimeWitnessError("time_authentication", "current-time proof is not trusted") from exc
    return evidence


def build_time_receipt(
    *,
    environment: str,
    evaluated_at: str,
    nonce_sha256: str,
    purpose: str,
    subject_sha256: str,
    trust_proof_sha256: str,
    trust_root_id: str,
    witness_identity_sha256: str,
) -> bytes:
    """Canonical helper for configured/test witness implementations."""

    return canonical_json_bytes(
        {
            "environment": environment,
            "evaluated_at": evaluated_at,
            "nonce_sha256": nonce_sha256,
            "purpose": purpose,
            "schema_version": CURRENT_TIME_SCHEMA,
            "subject_sha256": subject_sha256,
            "trust_proof_sha256": trust_proof_sha256,
            "trust_root_id": trust_root_id,
            "witness_identity_sha256": witness_identity_sha256,
        }
    )


__all__ = [
    "AuthenticatedCurrentTimeWitness",
    "AuthenticatedTimeEvidence",
    "CURRENT_TIME_SCHEMA",
    "INSTALLED_PRODUCTION_TIME_SCHEMA",
    "PRODUCTION_TIME_CONFIGURATION_PATH",
    "PRODUCTION_TIME_PROVIDER_ID",
    "PRODUCTION_TIME_TRUST_ROOT_ID",
    "PRODUCTION_TIME_WITNESS_IDENTITY_SHA256",
    "CurrentTimeIssuer",
    "CurrentTimeWitnessError",
    "HMACCurrentTimeIssuer",
    "build_time_receipt",
    "configured_hmac_current_time_witness",
    "installed_production_current_time_witness",
    "obtain_current_time",
    "synthetic_hmac_current_time_witness_for_test",
    "validate_current_time_witness_configuration",
]
