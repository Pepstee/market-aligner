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
STAGED_CONFIG_SHA256 = "2ab67684897303a619283c94ecab166a840f4b9efbf1df90d7e67aab46ea31a7"
LEGACY_CONFIG_SHA256 = "db98c0b1071fb7eb34681a9765a4c943deba7749597299a7de808e009f8a95bb"
PINNED_VENV_PYTHON = Path("/home/gutua/software-factory/.control/market-aligner-recovery-20260820/environments/jaa-integration/bin/python")
PINNED_COMPONENT_ROOT = Path("/home/gutua")
PINNED_RUNTIME = Path("/home/gutua/.local/share/uv/python/cpython-3.12.13-linux-x86_64-gnu/bin/python3.12")
PINNED_RUNTIME_SHA256 = "d778d0b551287fb5f06c4464f78b616c086f8d42e94d8cfc209b12324cf937a1"
PINNED_PYVENV_SHA256 = "4716ef98127b9f94992bc78ab4f48c317d5067567ade669a88c72ef2b1b605a5"
PINNED_LINKS = {
    PINNED_VENV_PYTHON: "python3.12",
    PINNED_VENV_PYTHON.parent / "python3.12": "/home/gutua/.local/bin/python3.12",
    Path("/home/gutua/.local/bin/python3.12"): "/home/gutua/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu/bin/python3.12",
    Path("/home/gutua/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu"): "/home/gutua/.local/share/uv/python/cpython-3.12.13-linux-x86_64-gnu",
}
PINNED_CRYPTOGRAPHY_IDENTITY = {
    "cryptography_backend": "/home/gutua/software-factory/.control/market-aligner-recovery-20260820/environments/jaa-integration/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so",
    "cryptography_backend_sha256": "b66d4b275b58149f1d3aeed25f1f6128c5fcc70f8896895407da6fea46be12df",
    "cryptography_module": "/home/gutua/software-factory/.control/market-aligner-recovery-20260820/environments/jaa-integration/lib/python3.12/site-packages/cryptography/__init__.py",
    "cryptography_module_sha256": "9ad86e52b4dde0544e0a9518ad322a863cfab3a4fd763019ad5ee7675a0c9b6a",
    "cryptography_version": "49.0.0",
    "ed25519_signature_bytes": 64,
    "sys_executable": str(PINNED_VENV_PYTHON),
}


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


def _upgrade_exact(
    path: Path,
    value: bytes,
    *,
    previous: bytes,
    mode: int,
    expected_uid: int = 0,
) -> str:
    if not path.exists() and not path.is_symlink():
        return _exact_file(path, value, mode)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise FileExistsError(f"refusing to replace unsafe root target: {path}")
    current = path.read_bytes()
    if current == value:
        return "exact-replay"
    if current != previous:
        raise FileExistsError(f"refusing to overwrite unrecognized root target: {path}")
    temporary = path.with_name(f".{path.name}.upgrade-{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return "upgraded-exact-prior"


def _protected_path_components(path: Path) -> None:
    try:
        relative = path.relative_to(PINNED_COMPONENT_ROOT)
    except ValueError as exc:
        raise ValueError("runtime path escapes the reviewed component root") from exc
    current = PINNED_COMPONENT_ROOT
    candidates = (current, *(current / Path(*relative.parts[:index]) for index in range(1, len(relative.parts))))
    for current in candidates:
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(f"runtime path component is writable or not a directory: {current}")


def _verified_runtime_link(python: Path) -> Path:
    if python != PINNED_VENV_PYTHON or not python.is_absolute():
        raise ValueError("Python runtime link differs from the reviewed venv entry point")
    for link, expected_target in PINNED_LINKS.items():
        _protected_path_components(link)
        metadata = link.lstat()
        if not stat.S_ISLNK(metadata.st_mode) or os.readlink(link) != expected_target:
            raise ValueError(f"Python runtime symlink retargeted: {link}")
        target = Path(expected_target)
        if not target.is_absolute():
            lexical = Path(os.path.abspath(link.parent / target))
            if lexical != link.parent and link.parent not in lexical.parents:
                raise ValueError(f"relative Python runtime link escapes its directory: {link}")
    resolved = python.resolve(strict=True)
    _protected_path_components(resolved)
    metadata = resolved.stat()
    if (
        resolved != PINNED_RUNTIME
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 1000
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or hashlib.sha256(resolved.read_bytes()).hexdigest() != PINNED_RUNTIME_SHA256
    ):
        raise ValueError("resolved Python interpreter identity differs")
    pyvenv = PINNED_VENV_PYTHON.parents[1] / "pyvenv.cfg"
    _protected_path_components(pyvenv)
    pyvenv_metadata = pyvenv.stat()
    if (
        pyvenv.is_symlink()
        or not stat.S_ISREG(pyvenv_metadata.st_mode)
        or pyvenv_metadata.st_uid != 1000
        or stat.S_IMODE(pyvenv_metadata.st_mode) & 0o022
        or hashlib.sha256(pyvenv.read_bytes()).hexdigest() != PINNED_PYVENV_SHA256
    ):
        raise ValueError("pyvenv.cfg identity differs")
    probe = """import hashlib,json,sys
from pathlib import Path
import cryptography
import cryptography.hazmat.bindings._rust as rust
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
module=Path(cryptography.__file__).resolve(strict=True)
backend=Path(rust.__file__).resolve(strict=True)
print(json.dumps({"cryptography_backend":str(backend),"cryptography_backend_sha256":hashlib.sha256(backend.read_bytes()).hexdigest(),"cryptography_module":str(module),"cryptography_module_sha256":hashlib.sha256(module.read_bytes()).hexdigest(),"cryptography_version":cryptography.__version__,"ed25519_signature_bytes":len(Ed25519PrivateKey.generate().sign(b"runtime-probe")),"sys_executable":sys.executable},sort_keys=True))"""
    completed = subprocess.run(
        [str(python), "-I", "-c", probe],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    try:
        identity = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("cryptography runtime identity is not canonical JSON") from exc
    if completed.stderr or identity != PINNED_CRYPTOGRAPHY_IDENTITY:
        raise ValueError("cryptography import/runtime identity drifted")
    return python


def _legacy_unit(*, python: Path, key: Path) -> bytes:
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


def _unit(*, python: Path, key: Path) -> bytes:
    legacy = _legacy_unit(python=python, key=key).decode("utf-8")
    return legacy.replace(
        "PrivateTmp=true\n",
        "PrivateTmp=true\nRuntimeDirectory=gigabyte/majaa\nRuntimeDirectoryMode=0755\n",
    ).encode("utf-8")


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
    for source, label in ((staged_config, "staged config"), (service_source, "service source"), (device_key, "device key")):
        if not source.is_absolute() or source.is_symlink() or not source.resolve(strict=True).is_file():
            raise ValueError(f"{label} is not an exact regular file")
    verified_python = _verified_runtime_link(python)
    config_bytes = staged_config.read_bytes()
    if hashlib.sha256(config_bytes).hexdigest() != STAGED_CONFIG_SHA256:
        raise ValueError("staged current-time configuration hash differs")
    legacy_config_bytes = config_bytes + b"\n"
    if hashlib.sha256(legacy_config_bytes).hexdigest() != LEGACY_CONFIG_SHA256:
        raise ValueError("reviewed legacy current-time configuration hash differs")
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
        "config": _upgrade_exact(
            CONFIG_TARGET,
            config_bytes,
            previous=legacy_config_bytes,
            mode=0o600,
        ),
        "service": _exact_file(SERVICE_TARGET, service_source.read_bytes(), 0o755),
        "unit": _upgrade_exact(
            UNIT_TARGET,
            _unit(python=verified_python, key=device_key),
            previous=_legacy_unit(python=verified_python, key=device_key),
            mode=0o644,
        ),
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
