#!/usr/bin/env python3
"""Root-owned Ed25519 current-time service for the pinned JAA Unix protocol."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import stat
import struct
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REQUEST_SCHEMA = "jaa.external-current-time-request.v1"
RESPONSE_SCHEMA = "jaa.external-authenticated-current-time.v1"
PROVIDER_ID = "gigabyte-external-current-time-v1"
TRUST_ROOT_ID = "gigabyte-jaa-current-time-root-v1"
WITNESS_IDENTITY_SHA256 = hashlib.sha256(b"gigabyte-jaa-external-current-time-witness-v1").hexdigest()
PUBLIC_KEY_SHA256 = "31b02680db90773e2038e9f53d4f616dcaec5f6f4c07fd2e501a53d07e9e21ea"
MAXIMUM_REQUEST_BYTES = 16_384
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _private_key(path: Path) -> Ed25519PrivateKey:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("device key path is unsafe")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not resolved.is_file() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("device key is not a protected regular file")
    loaded = serialization.load_pem_private_key(resolved.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("device key is not Ed25519")
    public = loaded.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if hashlib.sha256(public).hexdigest() != PUBLIC_KEY_SHA256:
        raise ValueError("device key differs from the compiled current-time trust root")
    return loaded


def issue_response(request_bytes: bytes, private_key: Ed25519PrivateKey, *, clock=lambda: datetime.now(timezone.utc)) -> bytes:
    try:
        request = json.loads(request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("current-time request is invalid JSON") from exc
    required = {
        "environment", "nonce_b64", "provider_id", "purpose", "schema_version",
        "subject_sha256", "trust_root_id", "witness_identity_sha256",
    }
    if not isinstance(request, dict) or set(request) != required or _canonical(request) != request_bytes:
        raise ValueError("current-time request is not canonical or has wrong fields")
    try:
        nonce = base64.b64decode(request["nonce_b64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("current-time request nonce is invalid") from exc
    if (
        request["environment"] != "production"
        or request["provider_id"] != PROVIDER_ID
        or request["schema_version"] != REQUEST_SCHEMA
        or request["trust_root_id"] != TRUST_ROOT_ID
        or request["witness_identity_sha256"] != WITNESS_IDENTITY_SHA256
        or not isinstance(request["purpose"], str)
        or not _PURPOSE.fullmatch(request["purpose"])
        or not isinstance(request["subject_sha256"], str)
        or not _SHA256.fullmatch(request["subject_sha256"])
        or len(nonce) != 32
    ):
        raise ValueError("current-time request binding differs")
    observed = clock()
    if not isinstance(observed, datetime) or observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("current-time UTC clock is unavailable")
    unsigned = {
        "environment": "production",
        "evaluated_at": observed.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
        "purpose": request["purpose"],
        "schema_version": RESPONSE_SCHEMA,
        "subject_sha256": request["subject_sha256"],
        "trust_root_id": TRUST_ROOT_ID,
        "witness_identity_sha256": WITNESS_IDENTITY_SHA256,
    }
    return _canonical({**unsigned, "signature_b64": base64.b64encode(private_key.sign(_canonical(unsigned))).decode("ascii")})


def _receive(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    while length:
        chunk = connection.recv(length)
        if not chunk:
            raise ValueError("current-time request ended early")
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def serve(*, socket_path: Path, key_path: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("current-time service must run as UID 0")
    private_key = _private_key(key_path)
    socket_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent_metadata = socket_path.parent.lstat()
    if (
        socket_path.parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != 0
        or stat.S_IMODE(parent_metadata.st_mode) != 0o755
    ):
        raise ValueError("current-time socket directory is not root-owned and exact")
    if socket_path.exists() or socket_path.is_symlink():
        metadata = socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode):
            raise FileExistsError("current-time socket target exists and is not a socket")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chown(socket_path, 0, 0)
        os.chmod(socket_path, 0o600)
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    length = struct.unpack("!I", _receive(connection, 4))[0]
                    if length < 1 or length > MAXIMUM_REQUEST_BYTES:
                        raise ValueError("current-time request length is invalid")
                    response = issue_response(_receive(connection, length), private_key)
                    connection.sendall(struct.pack("!I", len(response)) + response)
                except (OSError, ValueError):
                    continue


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()
    serve(socket_path=args.socket, key_path=args.key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
