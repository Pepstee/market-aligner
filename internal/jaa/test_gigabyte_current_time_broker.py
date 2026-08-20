from __future__ import annotations

import os
import socket
import struct
import threading
from pathlib import Path

import pytest

from scripts import gigabyte_current_time_broker as broker


def _frame(value: bytes) -> bytes:
    return struct.pack("!I", len(value)) + value


class _ConnectedSocket:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        self.connection.close()

    def settimeout(self, value: float) -> None:
        self.connection.settimeout(value)

    def connect(self, _path: str) -> None:
        return None

    def recv(self, length: int) -> bytes:
        return self.connection.recv(length)

    def sendall(self, value: bytes) -> None:
        self.connection.sendall(value)


def test_uid1000_peer_is_authenticated_and_bytes_are_forwarded_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert os.geteuid() == broker.AUTHORIZED_CLIENT_UID
    assert os.getegid() == broker.AUTHORIZED_CLIENT_GID
    public_client, public_server = socket.socketpair()
    signer_client, signer_server = socket.socketpair()
    request = b'{"request":"exact"}'
    response = b'{"response":"signed-but-opaque"}'
    captured: list[bytes] = []

    def signer() -> None:
        with signer_server:
            length = struct.unpack("!I", broker._receive_exact(signer_server, 4))[0]
            captured.append(broker._receive_exact(signer_server, length))
            signer_server.sendall(_frame(response))

    thread = threading.Thread(target=signer)
    thread.start()
    monkeypatch.setattr(
        broker,
        "_peer_credentials",
        lambda connection: (
            (123, 1000, 1000) if connection is public_server else (456, 0, 0)
        ),
    )
    connected = _ConnectedSocket(signer_client)
    with public_client, public_server:
        public_client.sendall(_frame(request))
        broker.forward_once(
            public_server,
            signer_socket=Path("/root-only-signer.sock"),
            connector=lambda *_args, **_kwargs: connected,
        )
        assert broker._receive_frame(public_client) == response
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert captured == [request]


def test_broker_rejects_unauthorized_peer_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = socket.socketpair()
    monkeypatch.setattr(broker, "_peer_credentials", lambda _connection: (123, 1001, 1001))
    with client, server, pytest.raises(PermissionError, match="caller identity"):
        broker.forward_once(server, signer_socket=Path("/root-only-signer.sock"))


@pytest.mark.parametrize("length", [0, broker.MAXIMUM_FRAME_BYTES + 1])
def test_broker_rejects_malformed_or_oversize_frame(
    monkeypatch: pytest.MonkeyPatch,
    length: int,
) -> None:
    client, server = socket.socketpair()
    monkeypatch.setattr(broker, "_peer_credentials", lambda _connection: (123, 1000, 1000))
    with client, server:
        client.sendall(struct.pack("!I", length))
        with pytest.raises(ValueError, match="frame length"):
            broker.forward_once(server, signer_socket=Path("/root-only-signer.sock"))


def test_broker_rejects_substituted_non_root_signer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_client, public_server = socket.socketpair()
    signer_client, signer_server = socket.socketpair()
    monkeypatch.setattr(
        broker,
        "_peer_credentials",
        lambda connection: (
            (123, 1000, 1000) if connection is public_server else (456, 1000, 1000)
        ),
    )
    connected = _ConnectedSocket(signer_client)
    with public_client, public_server, signer_server:
        public_client.sendall(_frame(b"request"))
        with pytest.raises(PermissionError, match="signer identity"):
            broker.forward_once(
                public_server,
                signer_socket=Path("/substituted.sock"),
                connector=lambda *_args, **_kwargs: connected,
            )


def test_broker_artifact_refuses_drift(tmp_path: Path) -> None:
    target = tmp_path / "broker"
    target.write_bytes(b"unexpected")
    target.chmod(0o755)
    from scripts import install_gigabyte_current_time as installer

    with pytest.raises(FileExistsError, match="differing root target"):
        installer._exact_file(target, b"reviewed", 0o755)
