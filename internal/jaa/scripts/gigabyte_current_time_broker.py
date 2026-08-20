#!/usr/bin/env python3
"""Privilege-separated byte broker for the root-only JAA time signer."""

from __future__ import annotations

import argparse
import os
import socket
import stat
import struct
from pathlib import Path


MAXIMUM_FRAME_BYTES = 16_384
SOCKET_TIMEOUT_SECONDS = 2.0
AUTHORIZED_CLIENT_UID = 1000
AUTHORIZED_CLIENT_GID = 1000
ROOT_SIGNER_UID = 0


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ValueError("current-time broker frame ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    peer_option = getattr(socket, "SO_PEERCRED", None)
    if peer_option is None:
        raise PermissionError("current-time broker cannot authenticate Unix peers")
    return struct.unpack(
        "3i",
        connection.getsockopt(socket.SOL_SOCKET, peer_option, struct.calcsize("3i")),
    )


def _receive_frame(connection: socket.socket) -> bytes:
    length = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if length < 1 or length > MAXIMUM_FRAME_BYTES:
        raise ValueError("current-time broker frame length is invalid")
    return _receive_exact(connection, length)


def _send_frame(connection: socket.socket, payload: bytes) -> None:
    if type(payload) is not bytes or not payload or len(payload) > MAXIMUM_FRAME_BYTES:
        raise ValueError("current-time broker frame is invalid")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def forward_once(
    client: socket.socket,
    *,
    signer_socket: Path,
    connector=socket.socket,
    authorized_uid: int = AUTHORIZED_CLIENT_UID,
    authorized_gid: int = AUTHORIZED_CLIENT_GID,
) -> None:
    """Authenticate one local caller and forward exactly one framed exchange."""

    _pid, peer_uid, peer_gid = _peer_credentials(client)
    if peer_uid != authorized_uid or peer_gid != authorized_gid:
        raise PermissionError("current-time broker caller identity differs")
    request = _receive_frame(client)
    with connector(socket.AF_UNIX, socket.SOCK_STREAM) as signer:
        signer.settimeout(SOCKET_TIMEOUT_SECONDS)
        signer.connect(str(signer_socket))
        _signer_pid, signer_uid, _signer_gid = _peer_credentials(signer)
        if signer_uid != ROOT_SIGNER_UID:
            raise PermissionError("current-time broker signer identity differs")
        _send_frame(signer, request)
        response = _receive_frame(signer)
    _send_frame(client, response)


def serve(
    *,
    socket_path: Path,
    signer_socket: Path,
    authorized_uid: int = AUTHORIZED_CLIENT_UID,
    authorized_gid: int = AUTHORIZED_CLIENT_GID,
) -> None:
    if os.geteuid() != 0:
        raise PermissionError("current-time broker must run as UID 0")
    if authorized_uid != AUTHORIZED_CLIENT_UID or authorized_gid != AUTHORIZED_CLIENT_GID:
        raise ValueError("current-time broker client identity differs from compiled pins")
    if socket_path == signer_socket or not socket_path.is_absolute() or not signer_socket.is_absolute():
        raise ValueError("current-time broker socket paths are invalid")
    parent = socket_path.parent
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise ValueError("current-time broker directory is not root-owned and exact")
    if socket_path.exists() or socket_path.is_symlink():
        metadata = socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode):
            raise FileExistsError("current-time broker target exists and is not a socket")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chown(socket_path, 0, authorized_gid)
        os.chmod(socket_path, 0o620)
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(SOCKET_TIMEOUT_SECONDS)
                try:
                    forward_once(
                        connection,
                        signer_socket=signer_socket,
                        authorized_uid=authorized_uid,
                        authorized_gid=authorized_gid,
                    )
                except (OSError, PermissionError, TimeoutError, ValueError):
                    continue


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--signer-socket", type=Path, required=True)
    parser.add_argument("--client-uid", type=int, required=True)
    parser.add_argument("--client-gid", type=int, required=True)
    args = parser.parse_args()
    serve(
        socket_path=args.socket,
        signer_socket=args.signer_socket,
        authorized_uid=args.client_uid,
        authorized_gid=args.client_gid,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
