#!/usr/bin/env python3
"""Idempotently install, start and verify the pinned Gigabyte time service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.current_time import installed_production_current_time_witness, obtain_current_time  # noqa: E402

CONFIG_TARGET = Path("/etc/gigabyte/majaa/jaa-current-time-v1.json")
SOCKET_TARGET = Path("/run/gigabyte/majaa/jaa-current-time-v1.sock")
SERVICE_TARGET = Path("/usr/local/libexec/jaa-current-time-v1")
UNIT_TARGET = Path("/etc/systemd/system/jaa-current-time-v1.service")
STAGED_CONFIG_SHA256 = "db98c0b1071fb7eb34681a9765a4c943deba7749597299a7de808e009f8a95bb"


def _exact_file(path: Path, value: bytes, mode: int) -> str:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != mode
            or path.read_bytes() != value
        ):
            raise FileExistsError(f"refusing to overwrite differing root target: {path}")
        return "exact-replay"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return "created"


def _unit(*, python: Path, key: Path) -> bytes:
    value = f"""[Unit]
Description=Gigabyte JAA authenticated current-time service
After=local-fs.target

[Service]
Type=simple
User=root
Group=root
ExecStart={python} {SERVICE_TARGET} --socket {SOCKET_TARGET} --key {key}
Restart=on-failure
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictAddressFamilies=AF_UNIX
UMask=0077

[Install]
WantedBy=multi-user.target
"""
    return value.encode("utf-8")


def install(
    *,
    staged_config: Path,
    service_source: Path,
    device_key: Path,
    python: Path,
    activate: bool,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise PermissionError("installer must run as UID 0")
    for source, label in ((staged_config, "staged config"), (service_source, "service source"), (device_key, "device key"), (python, "Python runtime")):
        if not source.is_absolute() or source.is_symlink() or not source.resolve(strict=True).is_file():
            raise ValueError(f"{label} is not an exact regular file")
    config_bytes = staged_config.read_bytes()
    if hashlib.sha256(config_bytes).hexdigest() != STAGED_CONFIG_SHA256:
        raise ValueError("staged current-time configuration hash differs")
    configuration = json.loads(config_bytes)
    if configuration.get("service_socket") != str(SOCKET_TARGET) or configuration.get("service_peer_uid") != 0:
        raise ValueError("staged current-time configuration weakens the socket pins")
    if stat.S_IMODE(device_key.stat().st_mode) != 0o600:
        raise ValueError("device key permissions differ")
    for directory, mode in (
        (CONFIG_TARGET.parent, 0o700),
        (SERVICE_TARGET.parent, 0o755),
    ):
        directory.mkdir(mode=mode, parents=True, exist_ok=True)
        metadata = directory.stat()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError(f"root installation directory differs: {directory}")
    outcomes = {
        "config": _exact_file(CONFIG_TARGET, config_bytes, 0o600),
        "service": _exact_file(SERVICE_TARGET, service_source.read_bytes(), 0o755),
        "unit": _exact_file(UNIT_TARGET, _unit(python=python, key=device_key), 0o644),
    }
    if not activate:
        return {"activated": False, "outcomes": outcomes}
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", UNIT_TARGET.name], check=True)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not SOCKET_TARGET.exists():
        time.sleep(0.1)
    subprocess.run(["systemctl", "is-active", "--quiet", UNIT_TARGET.name], check=True)
    socket_metadata = SOCKET_TARGET.lstat()
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != 0
        or stat.S_IMODE(socket_metadata.st_mode) != 0o600
    ):
        raise ValueError("deployed current-time socket differs from the production pin")
    witness = installed_production_current_time_witness()
    evidence = obtain_current_time(
        witness,
        environment="production",
        purpose="deployment_verification",
        subject_sha256=STAGED_CONFIG_SHA256,
    )
    return {
        "activated": True,
        "configuration_sha256": STAGED_CONFIG_SHA256,
        "outcomes": outcomes,
        "verification_receipt_sha256": evidence.receipt_sha256,
        "witness_identity_sha256": evidence.witness_identity_sha256,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-config", type=Path, required=True)
    parser.add_argument("--service-source", type=Path, required=True)
    parser.add_argument("--device-key", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()
    try:
        result = install(
            staged_config=args.staged_config,
            service_source=args.service_source,
            device_key=args.device_key,
            python=args.python,
            activate=args.activate,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"current-time deployment refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
