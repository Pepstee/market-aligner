#!/usr/bin/env python3
"""Execute every applicable JAA host-profile test and bind exact run evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Sequence

try:
    from scripts import jaa_certification_profile as profile
except ModuleNotFoundError:  # Direct execution sets sys.path[0] to scripts/.
    import jaa_certification_profile as profile  # type: ignore[no-redef]


RUN_BUNDLE_SCHEMA = "jaa.certification-profile-run-bundle.v1"
RUN_BUNDLE_DOMAIN = b"jaa-certification-profile-run-bundle-v1\0"


def _new_directory(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise profile.CertificationProfileError(
            "run output directory must be a new absolute path"
        )
    path.mkdir(parents=True, mode=0o700)
    return path


def _executable(
    path: Path, repository_root: Path
) -> tuple[Path, dict[str, object]]:
    if not path.is_absolute() or "\0" in os.fspath(path):
        raise profile.CertificationProfileError("Python executable must be absolute")
    is_symlink = path.is_symlink()
    if is_symlink and path.parent != repository_root / ".venv" / "bin":
        raise profile.CertificationProfileError(
            "Python symlink must be the repository virtual-environment launcher"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise profile.CertificationProfileError(
            "Python executable is unavailable"
        ) from exc
    metadata = resolved.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise profile.CertificationProfileError("Python executable is invalid")
    launcher_metadata = path.lstat()
    identity: dict[str, object] = {
        "launcher": str(path),
        "launcher_is_symlink": is_symlink,
        "launcher_link_target": os.readlink(path) if is_symlink else None,
        "launcher_lstat": {
            "device": launcher_metadata.st_dev,
            "inode": launcher_metadata.st_ino,
            "size": launcher_metadata.st_size,
            "mtime_ns": launcher_metadata.st_mtime_ns,
            "ctime_ns": launcher_metadata.st_ctime_ns,
        },
        "resolved_target": str(resolved),
        "resolved_target_sha256": profile._file_sha256(resolved),
        "resolved_target_stat": {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
        },
    }
    return path, identity


def _write_bytes(path: Path, payload: bytes) -> str:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("short write while recording certification output")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(payload).hexdigest()


def execute(
    *,
    repository_root: Path,
    evidence_config: Path,
    output_directory: Path,
    python_executable: Path,
    timeout_seconds: int,
) -> tuple[dict[str, object], bool]:
    repository_root = profile._absolute_lexical_directory(
        repository_root, "repository root"
    )
    python_executable, python_identity = _executable(
        python_executable, repository_root
    )
    hooks = profile.load_evidence_config(evidence_config)
    document = profile.build_profile(repository_root, hooks)
    output_directory = _new_directory(output_directory)
    logs = output_directory / "logs"
    logs.mkdir(mode=0o700)

    evidence_by_id = {hook.evidence_id: hook for hook in hooks}
    required_runtime_evidence = {
        "jaa09_exact_corpus",
        "jaa10_external_control",
    }
    missing_runtime_evidence = required_runtime_evidence - evidence_by_id.keys()
    if missing_runtime_evidence:
        raise profile.CertificationProfileError(
            "certification runner lacks required runtime evidence: "
            + ", ".join(sorted(missing_runtime_evidence))
        )
    environment = dict(os.environ)
    environment.update(
        {
            "JAA_CERTIFIED_CORPUS_ROOT": str(
                evidence_by_id["jaa09_exact_corpus"].root
            ),
            "JAA_OPERATOR_CONTROL_ROOT": str(
                evidence_by_id["jaa10_external_control"].root
            ),
            "JAA_CERTIFICATION_EVIDENCE_CONFIG": str(evidence_config),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    outcomes: dict[str, str] = {}
    runs: list[dict[str, object]] = []
    for index, test in enumerate(document["applicable_tests"], start=1):
        print(f"[{index}/{len(document['applicable_tests'])}] {test}", flush=True)
        command = [
            str(python_executable),
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            test,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=repository_root,
                env=environment,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
            returncode: int | None = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
            status = "passed" if completed.returncode == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            returncode = None
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            status = "timeout"
        stdout_path = logs / f"{test}.stdout"
        stderr_path = logs / f"{test}.stderr"
        stdout_sha256 = _write_bytes(stdout_path, stdout)
        stderr_sha256 = _write_bytes(stderr_path, stderr)
        outcomes[test] = status
        runs.append(
            {
                "test": test,
                "command": command,
                "returncode": returncode,
                "status": status,
                "stdout": {
                    "path": stdout_path.relative_to(output_directory).as_posix(),
                    "sha256": stdout_sha256,
                    "bytes": len(stdout),
                },
                "stderr": {
                    "path": stderr_path.relative_to(output_directory).as_posix(),
                    "sha256": stderr_sha256,
                    "bytes": len(stderr),
                },
            }
        )

    all_passed = all(value == "passed" for value in outcomes.values())
    _, python_identity_after = _executable(python_executable, repository_root)
    if python_identity_after != python_identity:
        raise profile.CertificationProfileError(
            "Python runtime identity changed during certification"
        )
    execution_receipt: dict[str, object] | None = None
    if all_passed:
        execution_receipt = profile.bind_execution_results(document, outcomes)
    bundle: dict[str, object] = {
        "schema_version": RUN_BUNDLE_SCHEMA,
        "profile": document,
        "selection_receipt": profile.selection_receipt(document),
        "python_runtime": python_identity,
        "runs": runs,
        "execution_receipt": execution_receipt,
        "claims": {
            "all_applicable_profile_tests_passed": all_passed,
            "current_source_linux_execution_verified": document["claims"][
                "current_source_linux_execution_verified"
            ],
            "excluded_linux_tests_certified_by_this_bundle": False,
            "post_import_independent_certification_required": document["claims"][
                "post_import_independent_certification_required"
            ],
            "product_certified": False,
            "jaa11_certified": False,
        },
    }
    bundle["bundle_sha256"] = profile._domain_hash(RUN_BUNDLE_DOMAIN, bundle)
    profile._write_canonical(output_directory / "run-bundle.json", bundle)
    return bundle, all_passed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--evidence-config", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--python-executable", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1:
        print("certification run refused: timeout must be positive", file=sys.stderr)
        return 2
    try:
        bundle, all_passed = execute(**vars(args))
    except (
        profile.CertificationProfileError,
        OSError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"certification run refused: {exc}", file=sys.stderr)
        return 2
    print(f"bundle_sha256={bundle['bundle_sha256']}")
    return 0 if all_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
