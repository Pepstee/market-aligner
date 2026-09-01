"""Atomic external storage for private profiles and evidence ledgers.

Stage B implements the crash-coherent generation protocol accepted in
FIT-001 R7+R8+R9 (+R10B): one same-directory coordination leaf,
``generation.json`` (strict canonical v1 JSON + LF, self-hashed, <=4096
bytes), an exact six-step exclusive-lock publication order governed by an
explicit phase state machine, strict outcome taxonomy (proven durable
``in_progress`` versus ``profile_generation_outcome_unknown``), bounded
looped-pread reads, total descriptor ownership, and fresh-lock disk
classification as the sole recovery authority. Readers never write.
"""

from __future__ import annotations

import errno as _errno
import fcntl
import hashlib
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

import yaml

from market_aligner.config import (
    ProductPaths,
    ensure_private_directory,
    open_existing_private_data_root,
    owner_private_umask,
)
from market_aligner.llm.contracts import canonical_hash

from .schema import (
    CandidateProfile,
    CanonicalProfileProjectionReceipt,
    EvidenceItem,
    TrackProfile,
    validate_profile_id,
)

PROFILE_NAME = "profile.yaml"
EVIDENCE_NAME = "evidence.jsonl"
MANIFEST_NAME = "generation.json"
MANIFEST_SCHEMA = "market-aligner.profile-generation.v1"

# FIT-001 §6 resource bounds (canonical owner: data_home/profiles).
MAX_PROFILE_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 4_194_304
MAX_EVIDENCE_ROWS = 10_000  # exactly 10,000 reaches parsing; 10,001 refuses
MAX_MANIFEST_BYTES = 4_096

_CANONICAL_NAMES = (PROFILE_NAME, EVIDENCE_NAME, MANIFEST_NAME)
_CANONICAL_NAME_SET = frozenset(_CANONICAL_NAMES)


def _create_or_verify_text(path: Path, content: str) -> None:
    """Create immutable projection output, or verify an exact replay."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"projection target is not a regular file: {path.name}")
        if path.read_text(encoding="utf-8") != content:
            raise ValueError(f"canonical profile projection drift: {path.name}")
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


class ProfileGenerationOutcomeUnknown(RuntimeError):
    """The save call did not return success and durable state is unproved."""


class DurableInProgressSaveFailed(RuntimeError):
    """The save failed but a proven durable in_progress disposition exists."""


# Private deterministic fault seams for the acceptance campaign only.
# Production defaults leave these empty: no injected behavior exists.
_FAULTS: dict[str, BaseException] = {}


def _install_fault(boundary: str, exc: BaseException | None) -> None:
    """Private test seam; never part of production behavior."""
    if exc is None:
        _FAULTS.pop(boundary, None)
    else:
        _FAULTS[boundary] = exc


def _clear_faults() -> None:
    _FAULTS.clear()


@contextmanager
def _fault_at(boundary: str, exc: BaseException) -> Iterator[None]:
    _install_fault(boundary, exc)
    try:
        yield
    finally:
        _install_fault(boundary, None)


def _maybe_fault(boundary: str) -> None:
    exc = _FAULTS.get(boundary)
    if exc is not None:
        raise exc


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink)


def _require_private_dir_info(info: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} must be a real directory")
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(
            f"{label} must have exactly 0700 permissions "
            f"(got {oct(stat.S_IMODE(info.st_mode))}); refusing without chmod"
        )


def _require_private_file_info(
    info: os.stat_result, label: str, *, max_size: int | None = None
) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current user")
    if info.st_nlink != 1:
        raise ValueError(f"{label} must have exactly one link (nlink={info.st_nlink})")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(
            f"{label} must have exactly 0600 permissions "
            f"(got {oct(stat.S_IMODE(info.st_mode))}); refusing without chmod"
        )
    if max_size is not None and info.st_size > max_size:
        raise ValueError(f"{label} exceeds {max_size} bytes ({info.st_size}); refusing")


def _entry_exists(dir_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _strict_json_loads(raw: bytes | str):
    """JSON with duplicate-key and nonfinite-number rejection."""

    def _pairs(pairs):
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON key: {key}")
            seen[key] = value
        return seen

    def _constant(name: str):
        raise ValueError(f"nonfinite JSON constant: {name}")

    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


_FORBIDDEN_RAW_LEAF = frozenset(range(0x00, 0x20)) - {0x0A} | {0x7F}


def _split_evidence_rows(data: bytes) -> list[bytes]:
    """Literal-LF framing only; raw C0 (except framing LF) and DEL reject."""
    if data and not data.endswith(b"\n"):
        raise ValueError(
            "nonempty evidence.jsonl requires a final literal LF framing byte"
        )
    rows = data.split(b"\n")
    if rows and rows[-1] == b"":
        rows.pop()  # canonical final-LF convention
    for row in rows:
        for byte in row:
            if byte in _FORBIDDEN_RAW_LEAF:
                raise ValueError("raw control character in evidence JSONL bytes")
    return [row for row in rows if row.strip()]


_PROSE_ALLOWED = frozenset({0x09, 0x0A, 0x0D})


def _validate_item_strings(item: EvidenceItem) -> None:
    data = asdict(item)
    for field, value in data.items():
        if not isinstance(value, str):
            continue
        allowed = _PROSE_ALLOWED if field == "claim" else frozenset()
        for char in value:
            code = ord(char)
            if code == 0x7F or (code < 0x20 and code not in allowed):
                label = "human-prose" if field == "claim" else "plain"
                raise ValueError(
                    f"evidence field {field!r} ({label}) carries forbidden "
                    f"control character U+{code:04X}"
                )


def _build_manifest(
    *, state: str, profile_id: str, profile_sha256: str, evidence_sha256: str
) -> bytes:
    five = {
        "schema_version": MANIFEST_SCHEMA,
        "state": state,
        "profile_id": profile_id,
        "profile_file_sha256": profile_sha256,
        "evidence_file_sha256": evidence_sha256,
    }
    six = dict(five)
    six["generation_sha256"] = hashlib.sha256(_canonical_json(five).encode("utf-8")).hexdigest()
    payload = (_canonical_json(six) + "\n").encode("utf-8")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"generation manifest would exceed {MAX_MANIFEST_BYTES} bytes; refusing"
        )
    return payload


def _classify_manifest_bytes(data: bytes, profile_id: str) -> dict[str, Any]:
    """Strict-parse and fully validate one manifest document."""
    if not data:
        raise ValueError("generation manifest is empty")
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError(f"generation manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    parsed = _strict_json_loads(data)
    if not isinstance(parsed, dict):
        raise ValueError("generation manifest root must be an object")
    expected_keys = {
        "schema_version",
        "state",
        "profile_id",
        "profile_file_sha256",
        "evidence_file_sha256",
        "generation_sha256",
    }
    if set(parsed) != expected_keys:
        raise ValueError("generation manifest keys differ from the exact v1 schema")
    if parsed["schema_version"] != MANIFEST_SCHEMA:
        raise ValueError("unsupported generation manifest schema_version")
    if parsed["state"] not in ("in_progress", "committed"):
        raise ValueError(f"invalid generation state: {parsed['state']!r}")
    if parsed["profile_id"] != profile_id:
        raise ValueError("generation manifest binds a different profile")
    for field in ("profile_file_sha256", "evidence_file_sha256", "generation_sha256"):
        value = parsed[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)
        ):
            raise ValueError(f"generation manifest field {field} is not a sha256")
    five = {key: parsed[key] for key in expected_keys - {"generation_sha256"}}
    recomputed = hashlib.sha256(_canonical_json(five).encode("utf-8")).hexdigest()
    if recomputed != parsed["generation_sha256"]:
        raise ValueError("generation manifest self-hash mismatch")
    if _canonical_json(parsed) + "\n" != data.decode("utf-8"):
        raise ValueError("generation manifest bytes are not canonical")
    return parsed


class _RetainedDirectory:
    """One verified directory level in the retained descriptor chain.

    The descriptor is owned from construction: any validation failure after
    ``open`` closes it exactly once before re-raising, and the live attribute
    is assigned only after safe ownership is established. Levels below
    data_home are private (real current-UID exact 0700); levels above are
    bound only. Levels with a retained parent gain name-entry continuity.
    """

    def __init__(
        self,
        *,
        parent_fd: int | None,
        name: str | None,
        path_label: str,
        private: bool = True,
        open_path: str | None = None,
        locator_only: bool = False,
    ) -> None:
        self.parent_fd = parent_fd
        self.name = name
        self.path_label = path_label
        self.private = private and not locator_only
        # Locator-only levels (the parent ABOVE data_home) bind a stable
        # dev/ino/uid/mode anchor but ignore the platform-volatile nlink in
        # every later revalidation; strict levels compare full identity.
        self.ignore_nlink_in_revalidation = locator_only or not private
        self.locator_only = locator_only
        self.open_path = open_path
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        if parent_fd is None:
            assert open_path is not None, "topmost level needs an explicit open path"
            owned = os.open(open_path, flags)
        else:
            assert name is not None
            owned = os.open(name, flags, dir_fd=parent_fd)
        try:
            info = os.fstat(owned)
            identity = _identity(info)
            if self.private:
                _require_private_dir_info(info, path_label)
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"{path_label} must be a real directory")
        except BaseException:
            os.close(owned)
            raise
        self.fd = owned
        self.identity = identity

    def _comparable_identity(self) -> tuple[int, int, int, int]:
        """Identity fields that must stay stable for this level."""
        return self.identity[:4]

    def recapture(self) -> None:
        """Re-capture identity once for a legitimate bounded transition."""
        self.identity = _identity(os.fstat(self.fd))

    def name_entry_identity(self) -> tuple[int, int, int, int, int] | None:
        if self.parent_fd is None or self.name is None:
            return None
        return _identity(os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False))

    def _locator_path_unchanged(self) -> None:
        """Prove the locator pathname itself was not replaced (lstat, no-follow).

        A symlink at the locator path is rejected outright; a substituted
        directory inode fails stable dev/ino/uid/mode comparison against the
        retained descriptor.
        """
        if not self.locator_only or self.open_path is None:
            return
        info = os.lstat(self.open_path)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{self.path_label} path is now a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{self.path_label} path is no longer a directory")
        if _identity(info)[:4] != self.identity[:4]:
            raise ValueError(f"{self.path_label} path was replaced")

    def initial_proof(self) -> None:
        self._locator_path_unchanged()
        entry = self.name_entry_identity()
        if entry is not None and entry != self.identity:
            raise ValueError(f"{self.path_label} name entry drifted during open")

    def revalidate(self) -> None:
        self._locator_path_unchanged()
        info = os.fstat(self.fd)
        current = _identity(info)
        if self.ignore_nlink_in_revalidation:
            if current[:4] != self._comparable_identity():
                raise ValueError(f"{self.path_label} descriptor identity drifted")
        else:
            if current != self.identity:
                raise ValueError(f"{self.path_label} descriptor identity drifted")
        entry = self.name_entry_identity()
        if entry is not None:
            if self.ignore_nlink_in_revalidation:
                if entry[:4] != self._comparable_identity():
                    raise ValueError(f"{self.path_label} name entry drifted")
            elif entry != self.identity:
                raise ValueError(f"{self.path_label} name entry drifted")

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


def _pread_exact_bounded(
    fd: int, *, maximum: int, label: str, dir_fd: int | None, name: str | None,
    expected_identity: tuple,
) -> bytes:
    """Looped bounded pread equal to stable st_size plus one-byte growth probe.

    Never touches the file offset. Refuses oversize-before-allocation, early
    EOF, growth/extra bytes, post-read identity drift, and — when a retained
    parent/name pair is supplied — name-entry drift.
    """
    info = os.fstat(fd)
    if _identity(info) != expected_identity:
        raise ValueError(f"{label} identity drifted before read")
    if info.st_size > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes ({info.st_size}); refusing")
    remaining = info.st_size
    chunks: list[bytes] = []
    offset = 0
    while remaining:
        chunk = os.pread(fd, min(65536, remaining), offset)
        if not chunk:
            raise ValueError(f"{label} ended early during bounded read")
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    extra = os.pread(fd, 1, offset)
    if extra:
        raise ValueError(f"{label} grew beyond its captured size during read")
    after = os.fstat(fd)
    if _identity(after) != expected_identity or after.st_size != info.st_size:
        raise ValueError(f"{label} drifted after bounded read")
    if dir_fd is not None and name is not None:
        named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if _identity(named) != expected_identity:
            raise ValueError(f"{label} name entry drifted during bounded read")
    return b"".join(chunks)


def _close_chain(levels) -> None:
    root_parent, root, profiles, directory = levels
    try:
        fcntl.flock(directory.fd, fcntl.LOCK_UN)
    except OSError:
        pass
    for level in (directory, profiles, root, root_parent):
        level.close()


def _open_verified_leaf(dir_fd: int, name: str, maximum: int) -> tuple[bytes, tuple, int]:
    """Open O_NOFOLLOW, fully validate, bounded-read, and RETURN THE OPEN FD.

    Caller owns the returned descriptor until it closes it. Metadata, growth,
    identity, and name-entry continuity are all proven before return.
    """
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        _require_private_file_info(info, name, max_size=maximum)
        identity = _identity(info)
        named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if _identity(named) != identity:
            raise ValueError(f"{name} changed during open")
        data = _pread_exact_bounded(
            fd, maximum=maximum, label=name, dir_fd=dir_fd, name=name,
            expected_identity=identity,
        )
        return data, identity, fd
    except BaseException:
        os.close(fd)
        raise


def _read_leaf_bounded(dir_fd: int, name: str, maximum: int) -> tuple[bytes, tuple]:
    """Open-and-close convenience wrapper over :func:`_open_verified_leaf`."""
    data, identity, fd = _open_verified_leaf(dir_fd, name, maximum)
    try:
        return data, identity
    finally:
        os.close(fd)


def _open_profile_chain(
    store: "ProfileStore",
    profile_id: str,
    *,
    exclusive: bool,
    wait: bool = True,
    create: bool = True,
) -> tuple[_RetainedDirectory, _RetainedDirectory, _RetainedDirectory, _RetainedDirectory]:
    """Open/retain parent->data_home->profiles-><profile_id>; flock last.

    Every fd-bearing level becomes an owned optional the moment its object
    exists; every failure unlocks (only when actually acquired) then closes
    directory/profiles/root/root_parent exactly once in reverse order. No
    unbound locals can escape this function's cleanup.
    """
    validate_profile_id(profile_id)
    if create:
        ensure_private_directory(store.paths.profiles, authority_root=store.paths.root)
    root_parent: _RetainedDirectory | None = None
    root: _RetainedDirectory | None = None
    profiles: _RetainedDirectory | None = None
    directory: _RetainedDirectory | None = None
    lock_acquired = False
    try:
        root_parent = _RetainedDirectory(
            parent_fd=None,
            name=None,
            path_label=f"data_home parent {store.paths.root.parent}",
            private=False,
            locator_only=True,
            open_path=str(store.paths.root.parent),
        )
        root = _RetainedDirectory(
            parent_fd=root_parent.fd,
            name=store.paths.root.name,
            path_label="data_home",
            private=True,
        )
        profiles = _RetainedDirectory(
            parent_fd=root.fd,
            name="profiles",
            path_label="data_home/profiles",
            private=True,
        )
        exists = _entry_exists(profiles.fd, profile_id)
        if not exists:
            if not create:
                raise FileNotFoundError(f"profile directory absent for {profile_id}")
            with owner_private_umask():
                os.mkdir(profile_id, 0o700, dir_fd=profiles.fd)
            # Legitimate pre-lock transition: creating the child changed the
            # profiles nlink. Recapture once here, before any later proof.
            profiles.recapture()
        directory = _RetainedDirectory(
            parent_fd=profiles.fd,
            name=profile_id,
            path_label="profile directory",
            private=True,
        )
        for level in (root_parent, root, profiles, directory):
            level.initial_proof()
        flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not wait:
            flags |= fcntl.LOCK_NB
        try:
            fcntl.flock(directory.fd, flags)
            lock_acquired = True
        except BlockingIOError as exc:
            raise ValueError("profile generation lock busy") from exc
        except OSError as exc:
            if exc.errno in (_errno.EAGAIN, _errno.EWOULDBLOCK):
                raise ValueError("profile generation lock busy") from exc
            raise ValueError(
                f"profile generation lock could not be acquired: {exc}"
            ) from exc
        for level in (root_parent, root, profiles, directory):
            level.revalidate()
        assert None not in (root_parent, root, profiles, directory)
        return root_parent, root, profiles, directory
    except BaseException:
        if directory is not None:
            if lock_acquired:
                try:
                    fcntl.flock(directory.fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        for level in (directory, profiles, root, root_parent):
            if level is not None:
                level.close()
        raise


class CoherentProfileSnapshot:
    """Shared-lock retained-byte view of one coherent generation.

    Retains the original O_NOFOLLOW descriptors for BOTH content leaves AND
    generation.json. Every leaf is validated and bounded-read through its own
    retained fd; revalidation reuses the same descriptors without reopening.
    Manifest absence binds explicitly (legacy_unsealed, FIT refuses) and is
    re-proved absent through close.
    """

    def __init__(
        self,
        store: "ProfileStore",
        profile_id: str,
        *,
        wait: bool = True,
        require_committed_generation: bool = False,
    ) -> None:
        self.profile_id = validate_profile_id(profile_id)
        self._closed = False
        self.require_committed_generation = require_committed_generation
        self.legacy_unsealed = False
        self.manifest: dict[str, Any] | None = None
        self._leaf_fds: dict[str, int] = {}
        self._leaf_identities: dict[str, tuple[int, int, int, int, int]] = {}
        self._bytes: dict[str, bytes] = {}
        self._manifest_fd: int | None = None
        self._manifest_identity: tuple[int, int, int, int, int] | None = None
        self._levels = None
        try:
            levels = _open_profile_chain(
                store, self.profile_id, exclusive=False, wait=wait, create=False
            )
            self._levels = levels
            self._directory = levels[-1]
            for level in levels:
                level.revalidate()
            for name, bound in (
                (PROFILE_NAME, MAX_PROFILE_BYTES),
                (EVIDENCE_NAME, MAX_EVIDENCE_BYTES),
            ):
                data, identity, fd = _open_verified_leaf(self._directory.fd, name, bound)
                self._leaf_fds[name] = fd
                self._leaf_identities[name] = identity
                self._bytes[name] = data
            manifest_present = _entry_exists(self._directory.fd, MANIFEST_NAME)
            if manifest_present:
                data, identity, fd = _open_verified_leaf(
                    self._directory.fd, MANIFEST_NAME, MAX_MANIFEST_BYTES
                )
                self._manifest_fd = fd
                self._manifest_identity = identity
                self.manifest = _classify_manifest_bytes(data, self.profile_id)
                self._bytes[MANIFEST_NAME] = data
            else:
                if require_committed_generation:
                    raise ValueError(
                        "FIT requires a committed generation manifest; none exists"
                    )
                self.legacy_unsealed = True
                self._bytes[MANIFEST_NAME] = b""
            if self.manifest is not None:
                if self.manifest["state"] != "committed":
                    raise ValueError(
                        f"generation state {self.manifest['state']!r} refuses FIT"
                    )
                computed = {
                    "profile_file_sha256": hashlib.sha256(
                        self._bytes[PROFILE_NAME]
                    ).hexdigest(),
                    "evidence_file_sha256": hashlib.sha256(
                        self._bytes[EVIDENCE_NAME]
                    ).hexdigest(),
                }
                if (
                    self.manifest["profile_file_sha256"] != computed["profile_file_sha256"]
                    or self.manifest["evidence_file_sha256"]
                    != computed["evidence_file_sha256"]
                ):
                    raise ValueError(
                        "committed generation does not match the exact leaf bytes"
                    )
            self._parse()
        except BaseException:
            self.close()
            raise

    def _parse(self) -> None:
        payload = yaml.safe_load(self._bytes[PROFILE_NAME].decode("utf-8")) or {}
        if not isinstance(payload, dict):
            raise ValueError("profile.yaml root must be a mapping")
        if payload.get("profile_id") != self.profile_id:
            raise ValueError("profile.yaml binds a different profile_id")
        payload["tracks"] = {
            name: TrackProfile(
                **{
                    **track,
                    "evidence_ids": tuple(track.get("evidence_ids") or ()),
                    "gaps": tuple(track.get("gaps") or ()),
                }
            )
            for name, track in (payload.get("tracks") or {}).items()
        }
        for key in ("blind_spots", "unknowns", "exclusions"):
            payload[key] = tuple(payload.get(key) or ())
        self.profile = CandidateProfile(**payload)
        evidence: dict[str, EvidenceItem] = {}
        self.evidence_ledger: list[EvidenceItem] = []
        framed_rows = _split_evidence_rows(self._bytes[EVIDENCE_NAME])
        # Count BEFORE constructing any EvidenceItem: exactly 10,000 reaches
        # parsing; 10,001 refuses.
        if len(framed_rows) > MAX_EVIDENCE_ROWS:
            raise ValueError(
                f"evidence.jsonl carries {len(framed_rows)} nonblank rows; "
                f"at most {MAX_EVIDENCE_ROWS} reach parsing"
            )
        for row in framed_rows:
            item = EvidenceItem(**_strict_json_loads(row))
            _validate_item_strings(item)
            if item.evidence_id in evidence:
                raise ValueError(f"duplicate evidence_id: {item.evidence_id}")
            evidence[item.evidence_id] = item
            self.evidence_ledger.append(item)
        self.profile.validate_evidence(evidence)
        self.evidence = evidence
        self.context = self.profile.llm_context(evidence)
        self.hashes = {
            "profile_file_sha256": hashlib.sha256(self._bytes[PROFILE_NAME]).hexdigest(),
            "evidence_file_sha256": hashlib.sha256(self._bytes[EVIDENCE_NAME]).hexdigest(),
            "profile_sha256": canonical_hash(asdict(self.profile)),
            "evidence_ledger_sha256": canonical_hash(
                [asdict(item) for item in self.evidence_ledger]
            ),
            "profile_context_sha256": canonical_hash(self.context),
        }

    def leaf_fd(self, name: str) -> int:
        """Test/diagnostic seam: one retained content-leaf descriptor."""
        return self._leaf_fds[name]

    def revalidate(self) -> None:
        """Prove every retained descriptor and parent name entry unchanged.

        Content rereads reuse the RETAINED fds via looped pread (offset
        untouched) with exact byte comparison including the empty case. The
        manifest reuses its retained fd, or — when legacy-absent — re-proves
        exact continued absence.
        """
        if self._closed:
            raise ValueError("profile snapshot is closed")
        for level in self._levels:
            level.revalidate()
        for name in (PROFILE_NAME, EVIDENCE_NAME):
            fd = self._leaf_fds[name]
            expected = self._leaf_identities[name]
            current = _pread_exact_bounded(
                fd, maximum=len(self._bytes[name]), label=name,
                dir_fd=self._directory.fd, name=name, expected_identity=expected,
            )
            if current != self._bytes[name]:
                raise ValueError(f"{name} content drifted under the generation lock")
        if self._manifest_fd is not None:
            current = _pread_exact_bounded(
                self._manifest_fd,
                maximum=len(self._bytes[MANIFEST_NAME]),
                label=MANIFEST_NAME,
                dir_fd=self._directory.fd,
                name=MANIFEST_NAME,
                expected_identity=self._manifest_identity,
            )
            if current != self._bytes[MANIFEST_NAME]:
                raise ValueError("generation manifest drifted under the lock")
        elif not self.require_committed_generation:
            if _entry_exists(self._directory.fd, MANIFEST_NAME):
                raise ValueError("generation manifest appeared under the lock")

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        for fd in getattr(self, "_leaf_fds", {}).values():
            try:
                os.close(fd)
            except OSError:
                pass
        manifest_fd = getattr(self, "_manifest_fd", None)
        if manifest_fd is not None:
            try:
                os.close(manifest_fd)
            except OSError:
                pass
            self._manifest_fd = None
        levels = getattr(self, "_levels", None)
        if levels is not None:
            _close_chain(levels)
            self._levels = None


class ProfileStore:
    def __init__(self, data_home: str | Path | None = None) -> None:
        self.paths = ProductPaths.resolve(data_home).ensure()

    @classmethod
    def open_existing(cls, data_home: str | Path | None = None) -> "ProfileStore":
        """Public no-write owner seam for FIT and no-write tests.

        Consumes the config no-create seam FIRST, on the supplied lexical
        override or MARKET_ALIGNER_DATA_HOME spelling before any resolve could
        erase aliases: a symlinked root or ancestor refuses even when its
        target is an otherwise valid current-UID 0700 directory. The verified
        retained descriptor is identity-bound to the canonical API spelling,
        then the EXISTING canonical data_home and data_home/profiles chain is
        proved descriptor-safely (real current-UID 0700 directories,
        O_DIRECTORY|O_NOFOLLOW opens with retained-parent name-entry
        continuity). Verification descriptors are closed before return.
        Missing or unsafe chains refuse; nothing is ever ensured, mkdir'd,
        chmodded, or written.
        """
        instance = cls.__new__(cls)
        # Ordering contract: the lexical no-create seam runs FIRST and its
        # retained descriptor chain stays ALIVE across ProductPaths.resolve,
        # the canonical identity comparison, and the existing profiles-chain
        # validation below. Resolution happens only after seam success, and
        # every supplied name entry is revalidated through the retained chain
        # immediately before release; the chain closes in finally.
        verified_chain = open_existing_private_data_root(data_home)
        try:
            verified_identity = os.fstat(verified_chain.deepest_fd)
            instance.paths = ProductPaths.resolve(data_home)
            canonical_info = os.stat(instance.paths.root)
            if (canonical_info.st_dev, canonical_info.st_ino) != (
                verified_identity.st_dev,
                verified_identity.st_ino,
            ):
                raise ValueError(
                    "canonical data_home spelling does not bind the "
                    "verified private root"
                )
            root_parent = _RetainedDirectory(
                parent_fd=None,
                name=None,
                path_label=f"data_home parent {instance.paths.root.parent}",
                private=False,
                locator_only=True,
                open_path=str(instance.paths.root.parent),
            )
            try:
                root = _RetainedDirectory(
                    parent_fd=root_parent.fd,
                    name=instance.paths.root.name,
                    path_label="data_home",
                    private=True,
                )
                try:
                    profiles = _RetainedDirectory(
                        parent_fd=root.fd,
                        name="profiles",
                        path_label="data_home/profiles",
                        private=True,
                    )
                    try:
                        for level in (root_parent, root, profiles):
                            level.initial_proof()
                            level.revalidate()
                    finally:
                        profiles.close()
                finally:
                    root.close()
            finally:
                root_parent.close()
            # Final supplied-name-entry proof while every descriptor of the
            # lexical chain is still open; detects an ancestor renamed to
            # -old and symlinked after the seam returned (same inodes).
            verified_chain.revalidate()
            return instance
        finally:
            verified_chain.close()

    def directory(self, profile_id: str) -> Path:
        return self.paths.profiles / validate_profile_id(profile_id)

    def coherent_snapshot(
        self,
        profile_id: str,
        *,
        wait: bool = True,
        require_committed_generation: bool = True,
    ) -> CoherentProfileSnapshot:
        """The exact FIT seam: committed v1 generation required by default."""
        return CoherentProfileSnapshot(
            self,
            profile_id,
            wait=wait,
            require_committed_generation=require_committed_generation,
        )

    def snapshot(
        self,
        profile_id: str,
        *,
        wait: bool = True,
        require_committed_generation: bool = False,
    ) -> CoherentProfileSnapshot:
        """Coherent view; absent manifest yields explicit legacy_unsealed."""
        return CoherentProfileSnapshot(
            self,
            profile_id,
            wait=wait,
            require_committed_generation=require_committed_generation,
        )

    def load(self, profile_id: str) -> tuple[CandidateProfile, dict[str, EvidenceItem]]:
        """Ordinary owner load over the coherent snapshot path.

        Explicit non-FIT compatibility: a manifest-absent pair loads as
        legacy_unsealed after strict leaf validation; any PRESENT-but-invalid
        or unsafe manifest refuses.
        """
        snapshot = self.snapshot(profile_id, require_committed_generation=False)
        try:
            return snapshot.profile, snapshot.evidence
        finally:
            snapshot.close()

    def list_profile_ids(self) -> list[str]:
        return sorted(
            child.name
            for child in self.paths.profiles.iterdir()
            if child.is_dir() and child.joinpath(PROFILE_NAME).is_file()
        )

    def save_projection(
        self,
        profile: CandidateProfile,
        evidence: list[EvidenceItem],
        receipt: CanonicalProfileProjectionReceipt,
    ) -> None:
        """Persist one canonical projection without permitting in-place drift."""
        evidence_by_id = {item.evidence_id: item for item in evidence}
        if len(evidence_by_id) != len(evidence):
            raise ValueError("duplicate evidence_id")
        profile.validate_evidence(evidence_by_id)
        if receipt.profile_id != profile.profile_id:
            raise ValueError("projection receipt targets another profile")
        profile_sha256 = hashlib.sha256(
            json.dumps(
                asdict(profile),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        evidence_sha256 = hashlib.sha256(
            json.dumps(
                [asdict(item) for item in evidence],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        if (
            receipt.profile_sha256 != profile_sha256
            or receipt.evidence_ledger_sha256 != evidence_sha256
        ):
            raise ValueError("projection receipt differs from profile content")
        directory = self.directory(profile.profile_id)
        profile_text = yaml.safe_dump(
            asdict(profile), sort_keys=False, allow_unicode=True, width=100
        )
        ledger_text = "".join(
            json.dumps(asdict(item), ensure_ascii=False, sort_keys=True) + "\n"
            for item in sorted(evidence, key=lambda item: item.evidence_id)
        )
        receipt_text = json.dumps(
            receipt.document(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        _create_or_verify_text(directory / PROFILE_NAME, profile_text)
        _create_or_verify_text(directory / EVIDENCE_NAME, ledger_text)
        _create_or_verify_text(directory / "projection-receipt.json", receipt_text)

    # ------------------------------------------------------------------
    # Crash-coherent publication protocol (explicit phase state machine)
    # ------------------------------------------------------------------

    def _make_temp(
        self,
        dir_fd: int,
        name_hint: str,
        payload: bytes,
        *,
        boundary_prefix: str | None = None,
    ) -> tuple[str, tuple]:
        """Create/write/fsync one same-directory 0600 temp; close exactly once.

        ``boundary_prefix`` stages the private rollback fault hooks at their
        actual completed steps (create/write/fsync); production passes None.
        Ownership is obtained only after a successful ``O_EXCL`` open; until
        then the generated name is never unlinked.  Successful close happens
        inside the protected ``try`` and sets the ``fd_closed`` sentinel so
        the handler never double-closes; a failed first close is sticky and
        forces :class:`ProfileGenerationOutcomeUnknown` even when a retry or
        the path cleanup later proves the name absent.
        """
        temporary = f".tmp-{name_hint}.{os.getpid()}.{os.urandom(6).hex()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = -1
        fd_closed = False  # sentinel: set only after a successful os.close
        close_failed = False  # sticky: first success-path close raised

        try:
            with owner_private_umask():
                descriptor = os.open(temporary, flags, 0o600, dir_fd=dir_fd)
                if boundary_prefix:
                    _maybe_fault(f"{boundary_prefix}_temp_create")
                os.fchmod(descriptor, 0o600)
                view = memoryview(payload)
                while view:
                    view = view[os.write(descriptor, view) :]
                if boundary_prefix:
                    _maybe_fault(f"{boundary_prefix}_temp_write")
                os.fsync(descriptor)
                if boundary_prefix:
                    _maybe_fault(f"{boundary_prefix}_temp_fsync")
                info = os.fstat(descriptor)
                _require_private_file_info(info, temporary)
                if info.st_size != len(payload):
                    raise ValueError(f"temp {temporary} wrote {info.st_size} bytes")
                identity = _identity(info)
                try:
                    os.close(descriptor)
                except OSError:
                    close_failed = True
                    raise
                fd_closed = True
            return temporary, identity

        except BaseException as exc:
            close_proved = False
            if descriptor >= 0 and not fd_closed:
                try:
                    os.close(descriptor)
                    close_proved = True
                except OSError:
                    pass
            if descriptor >= 0:
                cleanup_proved = True
                try:
                    os.unlink(temporary, dir_fd=dir_fd)
                    os.fsync(dir_fd)
                    if _entry_exists(dir_fd, temporary):
                        cleanup_proved = False
                except BaseException:
                    cleanup_proved = False
                if close_proved and cleanup_proved and not close_failed:
                    raise
                raise ProfileGenerationOutcomeUnknown(
                    "temp failure cleanup could not be proved"
                ) from exc
            else:
                try:
                    absent = not _entry_exists(dir_fd, temporary)
                except BaseException:
                    raise ProfileGenerationOutcomeUnknown(
                        "temp name absence could not be proved"
                    ) from exc
                if absent:
                    raise
                raise ProfileGenerationOutcomeUnknown(
                    "pre-existing name collision during temp creation"
                ) from exc

    def _rename_temp(
        self, dir_fd: int, temporary: str, target: str, expected: tuple, maximum: int
    ) -> None:
        os.rename(temporary, target, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        data, seen_identity, fd = _open_verified_leaf(dir_fd, target, maximum)
        try:
            if seen_identity != expected:
                raise ValueError(f"renamed {target} identity mismatch")
        finally:
            os.close(fd)
        del data

    def _reopen_and_verify_leaf(self, dir_fd: int, name: str, payload: bytes) -> None:
        data, _seen, fd = _open_verified_leaf(dir_fd, name, max(len(payload), 1))
        try:
            if data != payload:
                raise ValueError(f"published {name} content does not match")
        finally:
            os.close(fd)

    def _verify_manifest_entry(
        self, dir_fd: int, expected_bytes: bytes, expected_identity: tuple
    ) -> None:
        data, identity = _read_leaf_bounded(dir_fd, MANIFEST_NAME, MAX_MANIFEST_BYTES)
        if identity != expected_identity:
            raise ValueError("generation manifest identity drifted")
        if data != expected_bytes:
            raise ValueError("generation manifest bytes drifted")

    def save(self, profile: CandidateProfile, evidence: list[EvidenceItem]) -> None:
        """Publish one sealed generation; returns None only after the final
            committed durability barrier and exact revalidation.

        Phase taxonomy (exact, no inference): ``pre_mutation`` failures may
        re-raise the ORIGINAL error only when every pre-captured identity is
        freshly proven exactly unchanged, otherwise
        :class:`ProfileGenerationOutcomeUnknown`;
        ``initial_rename_unbarriered`` is always unknown;
        ``durable_in_progress`` failures freshly prove the exact durable
        in_progress manifest then raise
        :class:`DurableInProgressSaveFailed`, unknown when unprovable;
        ``committed_rename_unbarriered`` routes through the exact rollback
        republish (full temp write/fsync/rename/dirfsync/revalidation) yielding
        durable-in-progress, otherwise unknown. Success returns only after
        the final durability barrier and exact revalidation.
        """
        if len(evidence) > MAX_EVIDENCE_ROWS:
            raise ValueError(
                f"at most {MAX_EVIDENCE_ROWS} evidence rows reach validation; got "
                f"{len(evidence)}"
            )
        evidence_by_id = {item.evidence_id: item for item in evidence}
        if len(evidence_by_id) != len(evidence):
            raise ValueError("duplicate evidence_id")
        profile.validate_evidence(evidence_by_id)
        for item in evidence:
            _validate_item_strings(item)
        profile_bytes = yaml.safe_dump(
            asdict(profile), sort_keys=False, allow_unicode=True, width=100
        ).encode("utf-8")
        if len(profile_bytes) > MAX_PROFILE_BYTES:
            raise ValueError("profile.yaml exceeds its bound")
        ledger_bytes = "".join(
            json.dumps(asdict(item), ensure_ascii=False, sort_keys=True) + "\n"
            for item in sorted(evidence, key=lambda item: item.evidence_id)
        ).encode("utf-8")
        if len(ledger_bytes) > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence.jsonl exceeds its bound")
        profile_sha = hashlib.sha256(profile_bytes).hexdigest()
        evidence_sha = hashlib.sha256(ledger_bytes).hexdigest()
        in_progress = _build_manifest(
            state="in_progress",
            profile_id=profile.profile_id,
            profile_sha256=profile_sha,
            evidence_sha256=evidence_sha,
        )
        committed = _build_manifest(
            state="committed",
            profile_id=profile.profile_id,
            profile_sha256=profile_sha,
            evidence_sha256=evidence_sha,
        )
        levels = _open_profile_chain(
            self, profile.profile_id, exclusive=True, wait=True, create=True
        )
        root_parent, root, profiles, directory = levels
        temps: list[str] = []
        # Explicit phase; set immediately BEFORE each potentially mutating op.
        phase = "pre_mutation"
        # Pre-mutation capture: directory identity plus exact present/absent
        # name-entry identities for the three canonical names.
        pre_dir_identity = directory.identity
        pre_names = frozenset(os.listdir(directory.fd))
        if not pre_names.issubset(_CANONICAL_NAME_SET):
            _close_chain(levels)
            raise ValueError("profile directory contains an unrelated entry")
        prior_manifest_bytes = b""
        prior_manifest_identity: tuple | None = None
        pre_entries: dict[str, tuple | None] = {}
        prior_leaf_captures: dict[str, tuple[bytes, tuple]] = {}
        try:
            for name in _CANONICAL_NAMES:
                try:
                    info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                    pre_entries[name] = _identity(info)
                except FileNotFoundError:
                    pre_entries[name] = None
            # Strict O_NOFOLLOW classification of every PRESENT content leaf
            # under the held EX lock, BEFORE any temp or canonical mutation.
            # Each present leaf keeps a retained fd/identity/bytes/hash until
            # the deterministic pre-rename revalidation below closes it.
            prior_leaves: dict[str, tuple[bytes, tuple, int]] = {}
            try:
                for name, bound in ((PROFILE_NAME, MAX_PROFILE_BYTES), (EVIDENCE_NAME, MAX_EVIDENCE_BYTES)):
                    if pre_entries[name] is not None:
                        data, identity, fd = _open_verified_leaf(directory.fd, name, bound)
                        prior_leaves[name] = (data, identity, fd)
                if pre_entries[MANIFEST_NAME] is not None:
                    prior_manifest_bytes, prior_manifest_identity = _read_leaf_bounded(
                        directory.fd, MANIFEST_NAME, MAX_MANIFEST_BYTES
                    )
                    prior_manifest = _classify_manifest_bytes(
                        prior_manifest_bytes, profile.profile_id
                    )
                    if prior_manifest["state"] == "committed":
                        # A committed generation binds BOTH exact leaf bytes.
                        for name in (PROFILE_NAME, EVIDENCE_NAME):
                            if pre_entries[name] is None:
                                raise ValueError(
                                    f"committed manifest requires {name}; it is absent"
                                )
                            expected_field = (
                                "profile_file_sha256"
                                if name == PROFILE_NAME
                                else "evidence_file_sha256"
                            )
                            actual = hashlib.sha256(prior_leaves[name][0]).hexdigest()
                            if prior_manifest[expected_field] != actual:
                                raise ValueError(
                                    f"committed manifest hash mismatch for {name}"
                                )
            except BaseException:
                for _data, _ident, fd in prior_leaves.values():
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                prior_leaves.clear()
                raise
            prior_leaf_captures.update(
                {name: (payload[0], payload[1]) for name, payload in prior_leaves.items()}
            )
            global _SAVE_LOCK_INTERCEPT
            if _SAVE_LOCK_INTERCEPT is not None:
                # Private test seam: exclusive authority is held, nothing has
                # mutated yet. Production default is None.
                _SAVE_LOCK_INTERCEPT(profile.profile_id)

            def absorb_dir_transition() -> None:
                """Strict dev/ino/uid/mode; recapture transient temp nlink drift.

                Same-directory temps legitimately bump this platform's
                directory link count while they exist, so mid-save checks bind
                only the immutable identity fields; the FINAL gate below
                requires the exact own-name net delta, catching any injected
                extra entry by completion time.
                """
                current = _identity(os.fstat(directory.fd))
                if current[:4] != pre_dir_identity[:4]:
                    raise ValueError("profile directory identity drifted during save")
                directory.recapture()

            # Exact revalidation immediately before the FIRST rename, then
            # deterministic close of every retained classification fd. Each
            # retained leaf is reread via looped pread at its exact contract
            # bound and compared byte-for-byte to its captured bytes — a
            # same-size in-place mutation cannot hide.
            for level in levels:
                level.revalidate()
            if prior_manifest_identity is not None:
                self._verify_manifest_entry(
                    directory.fd, prior_manifest_bytes, prior_manifest_identity
                )
            else:
                if _entry_exists(directory.fd, MANIFEST_NAME):
                    raise ValueError("generation manifest appeared before first rename")
            try:
                for name, (data, identity, fd) in prior_leaves.items():
                    maximum = (
                        MAX_PROFILE_BYTES if name == PROFILE_NAME else MAX_EVIDENCE_BYTES
                    )
                    current = _pread_exact_bounded(
                        fd,
                        maximum=maximum,
                        label=name,
                        dir_fd=directory.fd,
                        name=name,
                        expected_identity=identity,
                    )
                    if current != data:
                        raise ValueError(f"{name} content drifted before first rename")
            finally:
                for entry in prior_leaves.values():
                    try:
                        os.close(entry[2])
                    except OSError:
                        pass
                prior_leaves.clear()

            # Step 1: in_progress manifest barrier.
            temp, ident = self._make_temp(directory.fd, "gen", in_progress)
            temps.append(temp)
            _maybe_fault("after_manifest_temp_fsync")
            phase = "initial_rename_unbarriered"
            self._rename_temp(directory.fd, temp, MANIFEST_NAME, ident, MAX_MANIFEST_BYTES)
            temps.remove(temp)
            _maybe_fault("after_initial_rename")
            os.fsync(directory.fd)
            _maybe_fault("after_initial_dirfsync")
            self._verify_manifest_entry(directory.fd, in_progress, ident)
            absorb_dir_transition()
            # Only NOW is the step-1 durability barrier complete: later
            # failures may claim a proven durable in_progress disposition.
            phase = "durable_in_progress"
            _maybe_fault("after_step1_barrier")

            # Steps 2-3: content temps fsynced, then renamed under in_progress.
            ptemp, pident = self._make_temp(directory.fd, "prof", profile_bytes)
            temps.append(ptemp)
            etemp, eident = self._make_temp(directory.fd, "evd", ledger_bytes)
            temps.append(etemp)
            _maybe_fault("after_leaf_temp_fsync")
            absorb_dir_transition()
            self._verify_manifest_entry(directory.fd, in_progress, ident)
            self._rename_temp(directory.fd, ptemp, PROFILE_NAME, pident, MAX_PROFILE_BYTES)
            temps.remove(ptemp)
            self._rename_temp(directory.fd, etemp, EVIDENCE_NAME, eident, MAX_EVIDENCE_BYTES)
            temps.remove(etemp)
            _maybe_fault("after_leaf_renames")

            # Step 4: content-leaf publication barrier + exact verification.
            os.fsync(directory.fd)
            _maybe_fault("after_content_barrier")
            self._reopen_and_verify_leaf(directory.fd, PROFILE_NAME, profile_bytes)
            self._reopen_and_verify_leaf(directory.fd, EVIDENCE_NAME, ledger_bytes)
            self._verify_manifest_entry(directory.fd, in_progress, ident)
            absorb_dir_transition()
            _maybe_fault("after_content_verify")

            # Step 5: committed manifest rename.
            ctemp, cident = self._make_temp(directory.fd, "gen", committed)
            temps.append(ctemp)
            _maybe_fault("after_committed_temp_fsync")
            self._reopen_and_verify_leaf(directory.fd, PROFILE_NAME, profile_bytes)
            self._reopen_and_verify_leaf(directory.fd, EVIDENCE_NAME, ledger_bytes)
            self._verify_manifest_entry(directory.fd, in_progress, ident)
            phase = "committed_rename_unbarriered"
            self._rename_temp(directory.fd, ctemp, MANIFEST_NAME, cident, MAX_MANIFEST_BYTES)
            temps.remove(ctemp)
            _maybe_fault("after_committed_rename")

            # Step 6: committed-name durability barrier; success only here.
            os.fsync(directory.fd)
            _maybe_fault("after_final_dirfsync")
            final_names = frozenset(os.listdir(directory.fd))
            if final_names != _CANONICAL_NAME_SET:
                raise ValueError(
                    "profile directory entries differ from the exact canonical set"
                )
            self._verify_manifest_entry(directory.fd, committed, cident)
            self._reopen_and_verify_leaf(directory.fd, PROFILE_NAME, profile_bytes)
            self._reopen_and_verify_leaf(directory.fd, EVIDENCE_NAME, ledger_bytes)
            for level in levels:
                level.revalidate()
            phase = "committed"
            return
        except BaseException as exc:
            if isinstance(exc, ProfileGenerationOutcomeUnknown):
                raise
            if phase == "initial_rename_unbarriered":
                raise ProfileGenerationOutcomeUnknown(
                    "save failed between the initial rename and its barrier"
                ) from exc
            if phase == "committed_rename_unbarriered":
                self._rollback_republish(directory, temps, in_progress, exc)
                raise AssertionError("unreachable")  # rollback always raises
            if phase == "durable_in_progress":
                try:
                    current = _read_leaf_bounded(
                        directory.fd, MANIFEST_NAME, MAX_MANIFEST_BYTES
                    )
                    if current[1] != ident or current[0] != in_progress:
                        raise ValueError("durable in_progress not proven")
                except BaseException as proof_exc:
                    raise ProfileGenerationOutcomeUnknown(
                        "save failed and durable in_progress could not be proved"
                    ) from proof_exc
                raise DurableInProgressSaveFailed(
                    "save failed; proven durable in_progress generation"
                ) from exc
            # pre_mutation: original error may propagate ONLY when every own
            # temp is proven removed and everything captured before mutation
            # is freshly proven exactly unchanged.
            try:
                # Close any retained classification fds deterministically.
                for entry in prior_leaves.values():
                    try:
                        os.close(entry[2])
                    except OSError:
                        pass
                prior_leaves.clear()
                # Remove our own temps first, fsync the directory, and prove
                # each temp name absent; an unproved temp persistence must be
                # outcome-unknown rather than a silently "unchanged" prior.
                if temps:
                    for temp in list(temps):
                        os.unlink(temp, dir_fd=directory.fd)
                    os.fsync(directory.fd)
                    for temp in temps:
                        if _entry_exists(directory.fd, temp):
                            raise ValueError(f"temp {temp} persisted after unlink")
                    temps.clear()
                now_dir = _identity(os.fstat(directory.fd))
                if now_dir != pre_dir_identity:
                    raise ValueError("directory identity drifted in pre-mutation window")
                for name, expected in pre_entries.items():
                    present = _entry_exists(directory.fd, name)
                    if expected is None:
                        if present:
                            raise ValueError(f"{name} appeared in pre-mutation window")
                    else:
                        info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                        if _identity(info) != expected:
                            raise ValueError(f"{name} drifted in pre-mutation window")
                if prior_manifest_identity is not None:
                    self._verify_manifest_entry(
                        directory.fd, prior_manifest_bytes, prior_manifest_identity
                    )
                for name, (data, identity) in prior_leaf_captures.items():
                    reread = _read_leaf_bounded(
                        directory.fd,
                        name,
                        MAX_PROFILE_BYTES if name == PROFILE_NAME else MAX_EVIDENCE_BYTES,
                    )
                    if reread[0] != data or reread[1] != identity:
                        raise ValueError(f"{name} drifted in pre-mutation window")
            except BaseException as proof_exc:
                raise ProfileGenerationOutcomeUnknown(
                    "pre-mutation failure could not prove the unchanged prior state"
                ) from proof_exc
            raise
        finally:
            for temp in temps:
                try:
                    os.unlink(temp, dir_fd=directory.fd)
                except OSError:
                    pass
            _close_chain(levels)

    def _rollback_republish(
        self,
        directory: _RetainedDirectory,
        temps: list[str],
        in_progress: bytes,
        cause: BaseException,
    ) -> None:
        """Republish the exact prepared in_progress through its own barrier.

        Every step must succeed for a durable-in-progress claim; ANY failure
        yields :class:`ProfileGenerationOutcomeUnknown`.
        """
        try:
            rtemp, rident = self._make_temp(
                directory.fd, "gen", in_progress, boundary_prefix="rollback"
            )
            temps.append(rtemp)
            self._rename_temp(directory.fd, rtemp, MANIFEST_NAME, rident, MAX_MANIFEST_BYTES)
            temps.remove(rtemp)
            _maybe_fault("rollback_rename")
            os.fsync(directory.fd)
            _maybe_fault("rollback_dirfsync")
            self._verify_manifest_entry(directory.fd, in_progress, rident)
            _maybe_fault("rollback_revalidate")
        except BaseException as rollback_exc:
            if isinstance(cause, ProfileGenerationOutcomeUnknown):
                raise cause
            raise ProfileGenerationOutcomeUnknown(
                "save failed and rollback could not be proved"
            ) from rollback_exc
        raise DurableInProgressSaveFailed(
            "save failed; proven durable in_progress generation"
        ) from cause


# Private intercept consulted right after the exclusive lock is held (before
# any mutation). Production default is None: no injected behavior.
_SAVE_LOCK_INTERCEPT: Any = None
