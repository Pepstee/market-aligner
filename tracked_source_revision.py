"""Deterministic provenance for the checked-out, tracked product source."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_CONTENT_REVISION_DOMAIN = b"jaa-source-content-revision-v2\0"
SOURCE_CONTENT_REVISION_EXCLUSIONS = (b"runtime_evidence/",)


class TrackedSourceRevisionError(RuntimeError):
    """The tracked checkout cannot safely identify the product source."""


def source_content_revision_contract() -> dict[str, Any]:
    """Return the receipt contract implemented by :func:`source_content_revision`."""
    return {
        "algorithm": "sha256",
        "domain": "jaa-source-content-revision-v2",
        "entry_encoding": "uint64be-length-prefixed-path-mode-content",
        "scope": "current-tracked-source-tree",
        "ordering": "repository-relative-path-byte-order",
        "exclusions": ["runtime_evidence/"],
    }


def source_git_revision_contract() -> dict[str, str]:
    """Return the exact immutable Git identity recorded beside source bytes."""
    return {
        "algorithm": "git-commit-sha1",
        "reference": "HEAD^{commit}",
        "scope": "exact-source-commit",
    }


def _git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=repository,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace").strip()
        raise TrackedSourceRevisionError(
            f"git {' '.join(arguments)} failed: {detail}"
        )
    return completed.stdout


def _excluded(path: bytes) -> bool:
    return any(path.startswith(prefix) for prefix in SOURCE_CONTENT_REVISION_EXCLUSIONS)


def _safe_relative_path(path: bytes) -> bool:
    decoded = os.fsdecode(path)
    pure = PurePosixPath(decoded)
    return bool(decoded) and not pure.is_absolute() and all(
        component not in {"", ".", ".."} for component in pure.parts
    )


def source_git_revision(repository: str | Path) -> str:
    """Resolve the checkout's exact HEAD commit, refusing malformed identities."""
    repository_path = Path(repository)
    try:
        root = repository_path.resolve(strict=True)
    except OSError as exc:
        raise TrackedSourceRevisionError("source repository is missing") from exc
    if not root.is_dir():
        raise TrackedSourceRevisionError("source repository is not a directory")
    revision = _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip()
    if (
        len(revision) != 40
        or any(byte not in b"0123456789abcdef" for byte in revision)
    ):
        raise TrackedSourceRevisionError("source Git revision is not a SHA-1 commit")
    return revision.decode("ascii")


def source_content_revision(repository: str | Path) -> str:
    """Hash mode and actual bytes for every non-generated tracked source file.

    The Git index defines the repository-relative names and expected modes.  The
    checkout supplies the bytes, which are independently compared with the index
    object before being admitted to the digest.
    """
    repository_path = Path(repository)
    try:
        root = repository_path.resolve(strict=True)
    except OSError as exc:
        raise TrackedSourceRevisionError("source repository is missing") from exc
    if not root.is_dir():
        raise TrackedSourceRevisionError("source repository is not a directory")

    entries: list[tuple[bytes, bytes, bytes]] = []
    seen: set[bytes] = set()
    for record in _git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise TrackedSourceRevisionError("malformed tracked source path record")
        mode, object_id, stage = fields
        if stage != b"0":
            raise TrackedSourceRevisionError(
                f"unmerged tracked source path: {os.fsdecode(path)}"
            )
        if path in seen:
            raise TrackedSourceRevisionError(
                f"duplicate tracked source path: {os.fsdecode(path)}"
            )
        seen.add(path)
        if not _safe_relative_path(path):
            raise TrackedSourceRevisionError("unsafe tracked source path")
        if _excluded(path):
            continue
        if mode not in {b"100644", b"100755", b"120000"}:
            raise TrackedSourceRevisionError(
                f"unsupported tracked source mode {mode.decode()}: {os.fsdecode(path)}"
            )
        entries.append((path, mode, object_id))

    pathspec = (
        ".",
        ":(exclude)runtime_evidence/**",
    )
    if _git(root, "diff", "--name-only", "-z", "--", *pathspec) or _git(
        root, "diff", "--cached", "--name-only", "-z", "--", *pathspec
    ):
        raise TrackedSourceRevisionError("dirty tracked source tree")

    digest = hashlib.sha256(SOURCE_CONTENT_REVISION_DOMAIN)
    for path, declared_mode, object_id in sorted(entries):
        display_path = os.fsdecode(path)
        candidate = root / display_path
        try:
            status_before = candidate.lstat()
            candidate.parent.resolve(strict=True).relative_to(root)
            if declared_mode == b"120000":
                if not stat.S_ISLNK(status_before.st_mode):
                    raise TrackedSourceRevisionError(
                        f"dirty tracked source type: {display_path}"
                    )
                payload = os.fsencode(os.readlink(candidate))
                candidate.resolve(strict=True).relative_to(root)
                actual_mode = b"120000"
            else:
                if not stat.S_ISREG(status_before.st_mode):
                    raise TrackedSourceRevisionError(
                        f"non-regular tracked source refused: {display_path}"
                    )
                payload = candidate.read_bytes()
                actual_mode = b"100755" if status_before.st_mode & 0o111 else b"100644"
            status_after = candidate.lstat()
        except TrackedSourceRevisionError:
            raise
        except (OSError, ValueError) as exc:
            message = (
                "tracked symlink escapes or has a missing target"
                if declared_mode == b"120000"
                else "missing or unreadable tracked source file"
            )
            raise TrackedSourceRevisionError(f"{message}: {display_path}") from exc

        if actual_mode != declared_mode:
            raise TrackedSourceRevisionError(f"dirty tracked source mode: {display_path}")
        identity_before = (
            status_before.st_dev, status_before.st_ino, status_before.st_mode,
            status_before.st_size, status_before.st_mtime_ns,
        )
        identity_after = (
            status_after.st_dev, status_after.st_ino, status_after.st_mode,
            status_after.st_size, status_after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise TrackedSourceRevisionError("dirty tracked source tree")
        actual_object_id = _git(root, "hash-object", "--stdin", input_bytes=payload).strip()
        if actual_object_id != object_id:
            raise TrackedSourceRevisionError("dirty tracked source tree")
        for field in (path, declared_mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)

    return f"sha256:{digest.hexdigest()}"
