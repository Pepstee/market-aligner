"""Acquire and verify a receipt-bound Cloudflare Roughtime response.

The public acquisition entry point is the only network-capable surface in this
module. Verification is deterministic and offline. A verified response proves
that Cloudflare signed a time interval for the exact nonce derived from the
target receipt and caller-provided entropy; it does not certify JAA-10 or grant
submission authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA_VERSION = "jaa10.external-time-attestation.v1"
ISSUER = "Cloudflare-Roughtime-2"
ISSUER_HOST = "roughtime.cloudflare.com"
ISSUER_PORT = 2003
ISSUER_TRANSPORT = "udp"
ISSUER_PUBLIC_KEY_BASE64 = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
ISSUER_PUBLIC_KEY = base64.b64decode(ISSUER_PUBLIC_KEY_BASE64, validate=True)
ISSUER_PUBLIC_KEY_SHA256 = hashlib.sha256(ISSUER_PUBLIC_KEY).hexdigest()
ISSUER_KEY_SOURCE_URL = (
    "https://developers.cloudflare.com/time-services/roughtime/usage/"
)
PROTOCOL_VERSION = 0x8000000B
PROTOCOL_NAME = "draft-ietf-ntp-roughtime-11"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_RADIUS_SECONDS = 10
MAX_ATTEMPTS = 3
MAX_TIMEOUT_SECONDS = 10.0

_FRAME = b"ROUGHTIM"
_CERTIFICATE_CONTEXT = b"RoughTime v1 delegation signature--\x00"
_SIGNED_RESPONSE_CONTEXT = b"RoughTime v1 response signature\x00"
_NONCE_DOMAIN = b"jaa10-external-time-nonce-v1\x00"
_EVIDENCE_DOMAIN = b"jaa10-external-time-evidence-v1\x00"
_HEX_64 = frozenset("0123456789abcdef")


def _tag(value: bytes) -> int:
    if len(value) != 4:
        raise ValueError("Roughtime tag must contain four bytes")
    return struct.unpack("<I", value)[0]


TAG_CERT = _tag(b"CERT")
TAG_DELE = _tag(b"DELE")
TAG_INDX = _tag(b"INDX")
TAG_MAXT = _tag(b"MAXT")
TAG_MIDP = _tag(b"MIDP")
TAG_MINT = _tag(b"MINT")
TAG_NONC = _tag(b"NONC")
TAG_PATH = _tag(b"PATH")
TAG_PUBK = _tag(b"PUBK")
TAG_RADI = _tag(b"RADI")
TAG_ROOT = _tag(b"ROOT")
TAG_SIG = _tag(b"SIG\x00")
TAG_SREP = _tag(b"SREP")
TAG_SRV = _tag(b"SRV\x00")
TAG_VER = _tag(b"VER\x00")
TAG_ZZZZ = _tag(b"ZZZZ")


class ExternalTimeStatus(str, Enum):
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    ACQUISITION_FAILED = "acquisition_failed"


class ExternalTimeError(RuntimeError):
    """The external time package could not safely complete."""


class ExternalTimeIntegrityError(ExternalTimeError):
    """Roughtime bytes or their receipt binding are invalid."""


@dataclass(frozen=True, init=False)
class ExternalTimeAttestation:
    status: ExternalTimeStatus
    reason: str
    receipt_sha256: str
    entropy_sha256: str
    nonce_sha256: str
    request_sha256: str
    response_sha256: str | None
    midpoint_unix: int | None
    radius_seconds: int | None
    midpoint_utc: str | None
    lower_bound_utc: str | None
    upper_bound_utc: str | None
    evidence_sha256: str

    def verify(self) -> None:
        if not isinstance(self.status, ExternalTimeStatus):
            raise ExternalTimeIntegrityError("external time status is invalid")
        for value, label in (
            (self.receipt_sha256, "receipt hash"),
            (self.entropy_sha256, "entropy hash"),
            (self.nonce_sha256, "nonce hash"),
            (self.request_sha256, "request hash"),
            (self.evidence_sha256, "evidence hash"),
        ):
            if not _valid_digest(value):
                raise ExternalTimeIntegrityError(f"external time {label} is invalid")
        if self.response_sha256 is not None and not _valid_digest(
            self.response_sha256
        ):
            raise ExternalTimeIntegrityError(
                "external time response hash is invalid"
            )
        verified = self.status is ExternalTimeStatus.VERIFIED
        if verified:
            if (
                self.reason != "cloudflare_roughtime_response_verified"
                or self.response_sha256 is None
                or not isinstance(self.midpoint_unix, int)
                or isinstance(self.midpoint_unix, bool)
                or self.midpoint_unix < 1
                or not isinstance(self.radius_seconds, int)
                or isinstance(self.radius_seconds, bool)
                or not 0 <= self.radius_seconds <= MAX_RADIUS_SECONDS
            ):
                raise ExternalTimeIntegrityError(
                    "verified external time fields differ"
                )
            if (
                self.midpoint_utc != _utc(self.midpoint_unix)
                or self.lower_bound_utc
                != _utc(self.midpoint_unix - self.radius_seconds)
                or self.upper_bound_utc
                != _utc(self.midpoint_unix + self.radius_seconds)
            ):
                raise ExternalTimeIntegrityError(
                    "verified external time interval differs"
                )
        elif any(
            value is not None
            for value in (
                self.midpoint_unix,
                self.radius_seconds,
                self.midpoint_utc,
                self.lower_bound_utc,
                self.upper_bound_utc,
            )
        ):
            raise ExternalTimeIntegrityError(
                "failed external time result carries a time claim"
            )
        if self.evidence_sha256 != _evidence_hash(
            _evidence_core(
                status=self.status,
                reason=self.reason,
                receipt_sha256=self.receipt_sha256,
                entropy_sha256=self.entropy_sha256,
                nonce_sha256=self.nonce_sha256,
                request_sha256=self.request_sha256,
                response_sha256=self.response_sha256,
                midpoint=self.midpoint_unix,
                radius=self.radius_seconds,
            )
        ):
            raise ExternalTimeIntegrityError("external time evidence hash differs")

    def document(self) -> dict[str, object]:
        self.verify()
        return {
            "schema_version": SCHEMA_VERSION,
            "issuer": ISSUER,
            "issuer_endpoint": f"{ISSUER_HOST}:{ISSUER_PORT}",
            "issuer_transport": ISSUER_TRANSPORT,
            "issuer_public_key_base64": ISSUER_PUBLIC_KEY_BASE64,
            "issuer_public_key_sha256": ISSUER_PUBLIC_KEY_SHA256,
            "issuer_key_source_url": ISSUER_KEY_SOURCE_URL,
            "protocol": PROTOCOL_NAME,
            "status": self.status.value,
            "reason": self.reason,
            "receipt_sha256": self.receipt_sha256,
            "entropy_sha256": self.entropy_sha256,
            "nonce_sha256": self.nonce_sha256,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "midpoint_unix": self.midpoint_unix,
            "radius_seconds": self.radius_seconds,
            "midpoint_utc": self.midpoint_utc,
            "lower_bound_utc": self.lower_bound_utc,
            "upper_bound_utc": self.upper_bound_utc,
            "evidence_sha256": self.evidence_sha256,
            "external_time_authenticated": (
                self.status is ExternalTimeStatus.VERIFIED
            ),
            "certifies_slice": False,
            "submission_authority": False,
        }


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _domain_hash(domain: bytes, payload: bytes) -> str:
    digest = hashlib.sha256(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(_HEX_64)
    )


def _receipt_digest(target_receipt_bytes: bytes) -> str:
    if not isinstance(target_receipt_bytes, bytes) or not target_receipt_bytes:
        raise TypeError("target receipt must be non-empty exact bytes")
    return _sha256(target_receipt_bytes)


def _nonce(target_receipt_bytes: bytes, caller_entropy: bytes) -> bytes:
    receipt_sha256 = _receipt_digest(target_receipt_bytes)
    if (
        not isinstance(caller_entropy, bytes)
        or len(caller_entropy) < 32
        or len(caller_entropy) > 1024
    ):
        raise ValueError("caller entropy must contain 32 to 1024 bytes")
    digest = hashlib.sha512(_NONCE_DOMAIN)
    digest.update(bytes.fromhex(receipt_sha256))
    digest.update(len(caller_entropy).to_bytes(4, "big"))
    digest.update(caller_entropy)
    return digest.digest()[:32]


def _encode_message(values: Mapping[int, bytes]) -> bytes:
    if not values:
        return struct.pack("<I", 0)
    tags = sorted(values)
    if len(tags) != len(set(tags)):
        raise ValueError("duplicate Roughtime tag")
    payloads = [values[tag] for tag in tags]
    if any(not isinstance(value, bytes) or len(value) % 4 for value in payloads):
        raise ValueError("Roughtime values must be four-byte aligned")
    offsets: list[int] = []
    current = 0
    for payload in payloads[:-1]:
        current += len(payload)
        offsets.append(current)
    header = struct.pack("<I", len(tags))
    header += b"".join(struct.pack("<I", value) for value in offsets)
    header += b"".join(struct.pack("<I", value) for value in tags)
    return header + b"".join(payloads)


def _decode_message(data: bytes) -> dict[int, bytes]:
    if not isinstance(data, bytes) or len(data) < 4 or len(data) % 4:
        raise ExternalTimeIntegrityError("Roughtime message length is invalid")
    count = struct.unpack_from("<I", data)[0]
    if count == 0:
        if len(data) != 4:
            raise ExternalTimeIntegrityError("empty Roughtime message has payload")
        return {}
    header_length = 8 * count
    if header_length > len(data):
        raise ExternalTimeIntegrityError("Roughtime message is truncated")
    offsets = list(struct.unpack_from(f"<{count - 1}I", data, 4)) if count > 1 else []
    tags_offset = 4 * count
    tags = list(struct.unpack_from(f"<{count}I", data, tags_offset))
    if any(left >= right for left, right in zip(tags, tags[1:])):
        raise ExternalTimeIntegrityError("Roughtime tags are not strictly ordered")
    payload = data[header_length:]
    boundaries = [0, *offsets, len(payload)]
    if (
        any(offset % 4 for offset in offsets)
        or any(left > right for left, right in zip(boundaries, boundaries[1:]))
        or boundaries[-1] != len(payload)
    ):
        raise ExternalTimeIntegrityError("Roughtime offsets are invalid")
    return {
        tag: payload[boundaries[index] : boundaries[index + 1]]
        for index, tag in enumerate(tags)
    }


def _required(message: Mapping[int, bytes], tag: int, label: str) -> bytes:
    try:
        return message[tag]
    except KeyError as exc:
        raise ExternalTimeIntegrityError(f"missing Roughtime {label}") from exc


def _fixed(
    message: Mapping[int, bytes], tag: int, label: str, length: int
) -> bytes:
    value = _required(message, tag, label)
    if len(value) != length:
        raise ExternalTimeIntegrityError(f"invalid Roughtime {label} length")
    return value


def _u32(message: Mapping[int, bytes], tag: int, label: str) -> int:
    return struct.unpack("<I", _fixed(message, tag, label, 4))[0]


def _u64(message: Mapping[int, bytes], tag: int, label: str) -> int:
    return struct.unpack("<Q", _fixed(message, tag, label, 8))[0]


def _build_request(target_receipt_bytes: bytes, caller_entropy: bytes) -> tuple[bytes, bytes]:
    nonce = _nonce(target_receipt_bytes, caller_entropy)
    server_identity = hashlib.sha512(b"\xff" + ISSUER_PUBLIC_KEY).digest()[:32]
    values_length = len(nonce) + 4 + len(server_identity)
    tag_count = 4
    framing_and_header = 12 + 8 * tag_count
    padding_length = 1024 - framing_and_header - values_length
    if padding_length < 0 or padding_length % 4:
        raise AssertionError("Roughtime request padding contract differs")
    message = _encode_message(
        {
            TAG_NONC: nonce,
            TAG_SRV: server_identity,
            TAG_VER: struct.pack("<I", PROTOCOL_VERSION),
            TAG_ZZZZ: bytes(padding_length),
        }
    )
    request = _FRAME + struct.pack("<I", len(message)) + message
    if len(request) != 1024:
        raise AssertionError("Roughtime request must contain exactly 1024 bytes")
    return nonce, request


def _unframe(response_bytes: bytes) -> bytes:
    if not isinstance(response_bytes, bytes) or len(response_bytes) < 12:
        raise ExternalTimeIntegrityError("Roughtime response is truncated")
    if response_bytes[:8] != _FRAME:
        raise ExternalTimeIntegrityError("Roughtime response framing differs")
    declared = struct.unpack_from("<I", response_bytes, 8)[0]
    body = response_bytes[12:]
    if declared != len(body):
        raise ExternalTimeIntegrityError("Roughtime response length differs")
    return body


def _utc(seconds: int) -> str:
    try:
        value = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ExternalTimeIntegrityError("Roughtime timestamp is invalid") from exc
    return value.strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def _evidence_hash(document: Mapping[str, object]) -> str:
    return _domain_hash(_EVIDENCE_DOMAIN, _canonical_json(document))


def _evidence_core(
    *,
    status: ExternalTimeStatus,
    reason: str,
    receipt_sha256: str,
    entropy_sha256: str,
    nonce_sha256: str,
    request_sha256: str,
    response_sha256: str | None,
    midpoint: int | None,
    radius: int | None,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "issuer": ISSUER,
        "issuer_endpoint": f"{ISSUER_HOST}:{ISSUER_PORT}",
        "issuer_transport": ISSUER_TRANSPORT,
        "issuer_public_key_base64": ISSUER_PUBLIC_KEY_BASE64,
        "issuer_public_key_sha256": ISSUER_PUBLIC_KEY_SHA256,
        "issuer_key_source_url": ISSUER_KEY_SOURCE_URL,
        "protocol": PROTOCOL_NAME,
        "status": status.value,
        "reason": reason,
        "receipt_sha256": receipt_sha256,
        "entropy_sha256": entropy_sha256,
        "nonce_sha256": nonce_sha256,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "midpoint_unix": midpoint,
        "radius_seconds": radius,
        "midpoint_utc": _utc(midpoint) if midpoint is not None else None,
        "lower_bound_utc": (
            _utc(midpoint - radius)
            if midpoint is not None and radius is not None
            else None
        ),
        "upper_bound_utc": (
            _utc(midpoint + radius)
            if midpoint is not None and radius is not None
            else None
        ),
    }


def _attestation(
    *,
    status: ExternalTimeStatus,
    reason: str,
    receipt_sha256: str,
    entropy_sha256: str,
    nonce_sha256: str,
    request_sha256: str,
    response_sha256: str | None,
    midpoint: int | None = None,
    radius: int | None = None,
) -> ExternalTimeAttestation:
    core = _evidence_core(
        status=status,
        reason=reason,
        receipt_sha256=receipt_sha256,
        entropy_sha256=entropy_sha256,
        nonce_sha256=nonce_sha256,
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        midpoint=midpoint,
        radius=radius,
    )
    lower = midpoint - radius if midpoint is not None and radius is not None else None
    upper = midpoint + radius if midpoint is not None and radius is not None else None
    result = object.__new__(ExternalTimeAttestation)
    for field, value in (
        ("status", status),
        ("reason", reason),
        ("receipt_sha256", receipt_sha256),
        ("entropy_sha256", entropy_sha256),
        ("nonce_sha256", nonce_sha256),
        ("request_sha256", request_sha256),
        ("response_sha256", response_sha256),
        ("midpoint_unix", midpoint),
        ("radius_seconds", radius),
        ("midpoint_utc", _utc(midpoint) if midpoint is not None else None),
        ("lower_bound_utc", _utc(lower) if lower is not None else None),
        ("upper_bound_utc", _utc(upper) if upper is not None else None),
        ("evidence_sha256", _evidence_hash(core)),
    ):
        object.__setattr__(result, field, value)
    result.verify()
    return result


def verify_external_time_response(
    response_bytes: bytes,
    target_receipt_bytes: bytes,
    caller_entropy: bytes,
    prior_anchor: ExternalTimeAttestation | None = None,
) -> ExternalTimeAttestation:
    """Verify exact Roughtime bytes without using a network or local clock."""

    receipt_sha256 = _receipt_digest(target_receipt_bytes)
    entropy_sha256 = _sha256(caller_entropy) if isinstance(caller_entropy, bytes) else ""
    try:
        nonce, request = _build_request(target_receipt_bytes, caller_entropy)
    except (AssertionError, TypeError, ValueError) as exc:
        raise TypeError("external time verification inputs are invalid") from exc
    request_sha256 = _sha256(request)
    response_sha256 = _sha256(response_bytes) if isinstance(response_bytes, bytes) else None
    try:
        reply = _decode_message(_unframe(response_bytes))
        if _u32(reply, TAG_VER, "version") != PROTOCOL_VERSION:
            raise ExternalTimeIntegrityError("Roughtime version differs")
        # Cloudflare's deployed draft-11 service omits the optional echoed
        # NONC field. Freshness is still authenticated by the mandatory
        # nonce-to-Merkle-root proof below. If an echo is present, bind it too.
        echoed_nonce = reply.get(TAG_NONC)
        if echoed_nonce is not None and (
            len(echoed_nonce) != 32 or echoed_nonce != nonce
        ):
            raise ExternalTimeIntegrityError(
                "Roughtime nonce or receipt binding differs"
            )

        certificate = _decode_message(_required(reply, TAG_CERT, "certificate"))
        delegation_bytes = _required(certificate, TAG_DELE, "delegation")
        delegation_signature = _fixed(certificate, TAG_SIG, "delegation signature", 64)
        root_key = Ed25519PublicKey.from_public_bytes(ISSUER_PUBLIC_KEY)
        root_key.verify(
            delegation_signature,
            _CERTIFICATE_CONTEXT + delegation_bytes,
        )
        delegation = _decode_message(delegation_bytes)
        minimum = _u64(delegation, TAG_MINT, "minimum delegated time")
        maximum = _u64(delegation, TAG_MAXT, "maximum delegated time")
        online_key_bytes = _fixed(delegation, TAG_PUBK, "online public key", 32)

        signed_response_bytes = _required(reply, TAG_SREP, "signed response")
        response_signature = _fixed(reply, TAG_SIG, "response signature", 64)
        Ed25519PublicKey.from_public_bytes(online_key_bytes).verify(
            response_signature,
            _SIGNED_RESPONSE_CONTEXT + signed_response_bytes,
        )
        signed_response = _decode_message(signed_response_bytes)
        root = _fixed(signed_response, TAG_ROOT, "Merkle root", 32)
        midpoint = _u64(signed_response, TAG_MIDP, "midpoint")
        radius = _u32(signed_response, TAG_RADI, "radius")
        if maximum < minimum or not minimum <= midpoint <= maximum:
            raise ExternalTimeIntegrityError("Roughtime delegation range differs")
        if radius > MAX_RADIUS_SECONDS:
            raise ExternalTimeIntegrityError("Roughtime uncertainty radius is excessive")

        index = _u32(reply, TAG_INDX, "Merkle index")
        path = _required(reply, TAG_PATH, "Merkle path")
        if len(path) % 32:
            raise ExternalTimeIntegrityError("Roughtime Merkle path length differs")
        current = hashlib.sha512(b"\x00" + nonce).digest()
        while path:
            sibling, path = path[:32], path[32:]
            if index & 1:
                current = hashlib.sha512(b"\x01" + sibling + current[:32]).digest()
            else:
                current = hashlib.sha512(b"\x01" + current[:32] + sibling).digest()
            index >>= 1
        if index or current[:32] != root:
            raise ExternalTimeIntegrityError("Roughtime Merkle proof differs")

        if prior_anchor is not None:
            if (
                not isinstance(prior_anchor, ExternalTimeAttestation)
                or prior_anchor.status is not ExternalTimeStatus.VERIFIED
                or prior_anchor.midpoint_unix is None
                or prior_anchor.radius_seconds is None
            ):
                raise ExternalTimeIntegrityError("prior external time anchor is invalid")
            prior_anchor.verify()
            current_upper = midpoint + radius
            prior_lower = (
                prior_anchor.midpoint_unix - prior_anchor.radius_seconds
            )
            if current_upper < prior_lower:
                raise ExternalTimeIntegrityError("external time rollback detected")
    except InvalidSignature:
        failure_reason = "Roughtime signature verification failed"
        return _attestation(
            status=ExternalTimeStatus.VERIFICATION_FAILED,
            reason=failure_reason,
            receipt_sha256=receipt_sha256,
            entropy_sha256=entropy_sha256,
            nonce_sha256=_sha256(nonce),
            request_sha256=request_sha256,
            response_sha256=response_sha256,
        )
    except (ExternalTimeIntegrityError, TypeError, ValueError) as exc:
        return _attestation(
            status=ExternalTimeStatus.VERIFICATION_FAILED,
            reason=str(exc) or "external time verification failed",
            receipt_sha256=receipt_sha256,
            entropy_sha256=entropy_sha256,
            nonce_sha256=_sha256(nonce),
            request_sha256=request_sha256,
            response_sha256=response_sha256,
        )
    return _attestation(
        status=ExternalTimeStatus.VERIFIED,
        reason="cloudflare_roughtime_response_verified",
        receipt_sha256=receipt_sha256,
        entropy_sha256=entropy_sha256,
        nonce_sha256=_sha256(nonce),
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        midpoint=midpoint,
        radius=radius,
    )


def _exchange(request: bytes, attempts: int, timeout_seconds: float) -> bytes:
    addresses = socket.getaddrinfo(
        ISSUER_HOST,
        ISSUER_PORT,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP,
    )
    if not addresses:
        raise OSError("Cloudflare Roughtime address is unavailable")
    last_error: OSError | None = None
    for attempt in range(attempts):
        family, socktype, proto, _canonical, address = addresses[attempt % len(addresses)]
        try:
            with socket.socket(family, socktype, proto) as client:
                client.settimeout(timeout_seconds)
                client.connect(address)
                sent = client.send(request)
                if sent != len(request):
                    raise OSError("Roughtime request was partially sent")
                response = client.recv(MAX_RESPONSE_BYTES)
                if not response:
                    raise OSError("Roughtime response is empty")
                return response
        except OSError as exc:
            last_error = exc
    raise OSError("Cloudflare Roughtime did not answer") from last_error


def _publish_file(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    path.chmod(0o444)


def _publish_evidence(
    destination: Path,
    *,
    request: bytes,
    response: bytes | None,
    caller_entropy: bytes,
    attestation: ExternalTimeAttestation,
) -> None:
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    _publish_file(destination / "request.bin", request)
    _publish_file(destination / "entropy.bin", caller_entropy)
    if response is not None:
        _publish_file(destination / "response.bin", response)
    _publish_file(
        destination / "attestation.json",
        _canonical_json(attestation.document()),
    )
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def acquire_external_time_attestation(
    target_receipt_bytes: bytes,
    caller_entropy: bytes,
    destination: str | Path,
    *,
    attempts: int = MAX_ATTEMPTS,
    timeout_seconds: float = 3.0,
    prior_anchor: ExternalTimeAttestation | None = None,
) -> ExternalTimeAttestation:
    """Acquire one pinned Cloudflare Roughtime response and seal raw evidence."""

    if (
        not isinstance(attempts, int)
        or isinstance(attempts, bool)
        or not 1 <= attempts <= MAX_ATTEMPTS
    ):
        raise ValueError("external time attempts must be between one and three")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < float(timeout_seconds) <= MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("external time timeout is invalid")
    destination_path = Path(destination)
    if destination_path.exists() or destination_path.is_symlink():
        raise FileExistsError("external time evidence destination already exists")
    nonce, request = _build_request(target_receipt_bytes, caller_entropy)
    receipt_sha256 = _receipt_digest(target_receipt_bytes)
    entropy_sha256 = _sha256(caller_entropy)
    try:
        response = _exchange(request, attempts, float(timeout_seconds))
    except OSError as exc:
        attestation = _attestation(
            status=ExternalTimeStatus.ACQUISITION_FAILED,
            reason=str(exc) or "external time acquisition failed",
            receipt_sha256=receipt_sha256,
            entropy_sha256=entropy_sha256,
            nonce_sha256=_sha256(nonce),
            request_sha256=_sha256(request),
            response_sha256=None,
        )
        _publish_evidence(
            destination_path,
            request=request,
            response=None,
            caller_entropy=caller_entropy,
            attestation=attestation,
        )
        return attestation
    attestation = verify_external_time_response(
        response,
        target_receipt_bytes,
        caller_entropy,
        prior_anchor,
    )
    _publish_evidence(
        destination_path,
        request=request,
        response=response,
        caller_entropy=caller_entropy,
        attestation=attestation,
    )
    return attestation
