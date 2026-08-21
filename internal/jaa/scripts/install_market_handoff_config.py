#!/usr/bin/env python3
"""Create-or-exact installer for the production Market handoff authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
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
from career_automation.production_preparation_runner import (  # noqa: E402
    PRODUCTION_PREPARATION_CONFIG_PATH,
    production_preparation_configuration_bytes,
)

TARGET_MODE = 0o644
_DIRECTORY_WRITE_MASK = 0o022
_PRIOR_DEPLOYMENT_CONFIGURATION = (
    b'{"candidate_authority_path":"/home/gutua/software-factory/protected/'
    b'majaa-20260810/candidate/candidate_authority.json","candidate_authority_sha256":'
    b'"85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9",'
    b'"data_home":"/home/gutua/software-factory/.control/'
    b'market-aligner-recovery-20260820/live-data","output_root":"/home/gutua/'
    b'software-factory/protected/majaa-20260810/market-handoff","repository_root":'
    b'"/home/gutua/software-factory/projects/market-aligner-integration-20260820",'
    b'"research_archive_root_identity":"state/public-employer-research-v2",'
    b'"schema_version":"jaa.production-market-handoff-deployment.v1","trust_root_id":'
    b'"gigabyte-market-aligner-protected-outbox-v1"}'
)
_PRIOR_DEPLOYMENT_CONFIGURATION_SHA256 = (
    "5696865a3292a70692d405679a2adb5cdee4ff41be4149bbcd0965052c7dd04a"
)


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
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
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
    temporary_name = f".{target.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
    try:
        existing: bytes | None = None
        try:
            descriptor = os.open(
                target.name,
                os.O_RDONLY | flags,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            pass
        else:
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != expected_uid
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != TARGET_MODE
                ):
                    raise FileExistsError(
                        f"refusing to overwrite differing root target: {target}"
                    )
                existing = _read_all(descriptor)
            finally:
                os.close(descriptor)
        if existing == value:
            return "exact-replay"
        if existing is not None and (
            existing != _PRIOR_DEPLOYMENT_CONFIGURATION
            or hashlib.sha256(existing).hexdigest()
            != _PRIOR_DEPLOYMENT_CONFIGURATION_SHA256
        ):
            raise FileExistsError(
                f"refusing to overwrite differing root target: {target}"
            )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags,
            TARGET_MODE,
            dir_fd=parent_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != expected_uid:
                raise PermissionError("created configuration has an unexpected owner")
            os.fchmod(descriptor, TARGET_MODE)
            _write_all(descriptor, value)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if existing is None:
            try:
                os.link(
                    temporary_name,
                    target.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                replay = os.open(
                    target.name, os.O_RDONLY | flags, dir_fd=parent_descriptor
                )
                try:
                    metadata = os.fstat(replay)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != expected_uid
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != TARGET_MODE
                        or _read_all(replay) != value
                    ):
                        raise FileExistsError(
                            f"refusing to overwrite differing root target: {target}"
                        )
                finally:
                    os.close(replay)
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                temporary_name = ""
                outcome = "exact-replay"
            else:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                temporary_name = ""
                outcome = "created"
        else:
            current = os.open(
                target.name, os.O_RDONLY | flags, dir_fd=parent_descriptor
            )
            try:
                metadata = os.fstat(current)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != expected_uid
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != TARGET_MODE
                    or _read_all(current) != _PRIOR_DEPLOYMENT_CONFIGURATION
                ):
                    raise FileExistsError(
                        f"refusing to overwrite changed root target: {target}"
                    )
            finally:
                os.close(current)
            os.replace(
                temporary_name,
                target.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            temporary_name = ""
            outcome = "upgraded-exact-prior"
        os.fsync(parent_descriptor)
        return outcome
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
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


def install_preparation() -> dict[str, object]:
    """Install the distinct fixed preparation lifecycle authority."""
    if os.geteuid() != 0:
        raise PermissionError("installation requires root")
    value = production_preparation_configuration_bytes()
    outcome = _create_or_exact_at(
        PRODUCTION_PREPARATION_CONFIG_PATH,
        value,
        trusted_root=Path("/"),
        expected_uid=0,
    )
    return {
        "mode": "0644",
        "outcome": outcome,
        "owner_uid": 0,
        "schema_version": "jaa.production-preparation-config-installation.v1",
        "sha256": hashlib.sha256(value).hexdigest(),
        "target": str(PRODUCTION_PREPARATION_CONFIG_PATH),
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
    action.add_argument(
        "--print-preparation-config",
        action="store_true",
        help="write the exact preparation configuration bytes without installing",
    )
    action.add_argument(
        "--install-preparation",
        action="store_true",
        help="create-or-exact install the fixed preparation configuration",
    )
    args = parser.parse_args(argv)
    if args.print_config:
        sys.stdout.buffer.write(production_handoff_deployment_configuration_bytes())
        sys.stdout.buffer.flush()
        return 0
    if args.print_preparation_config:
        sys.stdout.buffer.write(production_preparation_configuration_bytes())
        sys.stdout.buffer.flush()
        return 0
    try:
        result = install_preparation() if args.install_preparation else install()
    except (OSError, ValueError) as exc:
        print(
            f"market-handoff configuration installation refused: {exc}", file=sys.stderr
        )
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
