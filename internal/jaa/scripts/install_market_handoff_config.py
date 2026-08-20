#!/usr/bin/env python3
"""Create-or-exact installer for the production Market handoff authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

JAA_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(JAA_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from career_automation.production_handoff_runner import (  # noqa: E402
    PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH,
    production_handoff_deployment_configuration_bytes,
)

TARGET_MODE = 0o644
_DIRECTORY_WRITE_MASK = 0o022


def _validate_directory(descriptor: int, *, expected_uid: int, label: str) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & _DIRECTORY_WRITE_MASK
    ):
        raise PermissionError(f"{label} is not an owner-controlled protected directory")


def _open_protected_parent(
    target: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
) -> int:
    if (
        not target.is_absolute()
        or not trusted_root.is_absolute()
        or ".." in target.parts
        or ".." in trusted_root.parts
    ):
        raise ValueError("installation paths must be absolute and normalized")
    try:
        relative_parent = target.parent.relative_to(trusted_root)
    except ValueError as exc:
        raise ValueError("installation target escapes its trusted root") from exc

    descriptor = os.open(
        trusted_root,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        _validate_directory(
            descriptor,
            expected_uid=expected_uid,
            label=str(trusted_root),
        )
        for component in relative_parent.parts:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                _validate_directory(
                    next_descriptor,
                    expected_uid=expected_uid,
                    label=str(target.parent),
                )
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write while installing configuration")
        remaining = remaining[written:]


def _create_or_exact_at(
    target: Path,
    value: bytes,
    *,
    trusted_root: Path,
    expected_uid: int,
) -> str:
    parent_descriptor = _open_protected_parent(
        target,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
    )
    flags = os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(
                target.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags,
                TARGET_MODE,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            descriptor = os.open(
                target.name,
                os.O_RDONLY | flags,
                dir_fd=parent_descriptor,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != expected_uid
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != TARGET_MODE
                    or _read_all(descriptor) != value
                ):
                    raise FileExistsError(
                        f"refusing to overwrite differing root target: {target}"
                    )
            finally:
                os.close(descriptor)
            return "exact-replay"

        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != expected_uid:
                raise PermissionError("created configuration has an unexpected owner")
            os.fchmod(descriptor, TARGET_MODE)
            _write_all(descriptor, value)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
        return "created"
    finally:
        os.close(parent_descriptor)


def install() -> dict[str, object]:
    """Install the exact compiled deployment authority at its fixed target."""
    if os.geteuid() != 0:
        raise PermissionError("installation requires root")
    value = production_handoff_deployment_configuration_bytes()
    outcome = _create_or_exact_at(
        PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH,
        value,
        trusted_root=Path("/"),
        expected_uid=0,
    )
    return {
        "mode": "0644",
        "outcome": outcome,
        "owner_uid": 0,
        "schema_version": "jaa.production-handoff-config-installation.v1",
        "sha256": hashlib.sha256(value).hexdigest(),
        "target": str(PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--print-config",
        action="store_true",
        help="write the exact canonical configuration bytes to stdout without installing",
    )
    action.add_argument(
        "--install",
        action="store_true",
        help="create-or-exact install the fixed root-owned configuration",
    )
    args = parser.parse_args(argv)
    if args.print_config:
        sys.stdout.buffer.write(production_handoff_deployment_configuration_bytes())
        sys.stdout.buffer.flush()
        return 0
    try:
        result = install()
    except (OSError, ValueError) as exc:
        print(f"market-handoff configuration installation refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
