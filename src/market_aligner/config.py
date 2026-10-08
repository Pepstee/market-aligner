"""Filesystem boundaries for product code and operator-owned data."""

from __future__ import annotations

import os
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Union

DATA_HOME_ENV = "MARKET_ALIGNER_DATA_HOME"

# Process-global serialization for cooperating owners of private material.
# Cooperating constructors, recovery scopes, and FIT transaction scopes take
# this lock around temporary restrictive-umask windows. This serializes
# cooperating in-process callers only; production process-one runs in a
# dedicated CLI process, and a noncooperating thread can observe the
# temporary restrictive umask (documented compatibility limitation).
_OWNER_PRIVATE_LOCK = threading.RLock()


def owner_private_lock() -> threading.RLock:
    """The process-global cooperating-owner lock (reentrant)."""
    return _OWNER_PRIVATE_LOCK


@contextmanager
def owner_private_umask() -> Iterator[None]:
    """Hold the cooperating lock and apply umask 0077 for the scope."""
    with _OWNER_PRIVATE_LOCK:
        previous = os.umask(0o077)
        try:
            yield
        finally:
            os.umask(previous)


def data_home(override: str | Path | None = None) -> Path:
    """Resolve the external data home without creating it.

    Product packages never contain profiles, credentials, raw vacancies, caches,
    or generated application material.  Operators can pin the boundary with the
    environment variable; the default remains outside any source checkout.
    """

    if override is not None:
        return Path(override).expanduser().resolve()
    configured = os.environ.get(DATA_HOME_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".local" / "share" / "market-aligner").resolve()


def lexical_data_home(override: str | Path | None = None) -> Path:
    """The operator spelling, expanded but never resolved.

    ``data_home`` canonicalizes with ``Path.resolve``, which silently erases
    alias evidence: a supplied path that traverses symlinks becomes its target.
    No-create verification must therefore inspect THIS spelling first; any
    symlink in it is refused instead of followed.
    """

    if override is not None:
        return Path(override).expanduser()
    configured = os.environ.get(DATA_HOME_ENV)
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "share" / "market-aligner"


@dataclass(frozen=True)
class ProductPaths:
    root: Path
    profiles: Path
    state: Path
    raw: Path
    cache: Path
    outputs: Path
    credentials: Path

    @classmethod
    def resolve(cls, override: str | Path | None = None) -> "ProductPaths":
        root = data_home(override)
        return cls(
            root=root,
            profiles=root / "profiles",
            state=root / "state",
            raw=root / "raw",
            cache=root / "cache",
            outputs=root / "outputs",
            credentials=root / "credentials",
        )

    def ensure(self) -> "ProductPaths":
        with owner_private_umask():
            for path in (
                self.root,
                self.profiles,
                self.state,
                self.raw,
                self.cache,
                self.outputs,
                self.credentials,
            ):
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(stat.S_IRWXU)
        return self


def _verify_dirinfo(info: os.stat_result, label: str, *, strict: bool) -> None:
    """Verify one directory lstat result.

    ``strict`` marks components at or below the bounded private authority
    root: they must be real, current-UID, exactly 0700. Ancestors above the
    authority root are checked only for real-directory type and no-symlink
    continuity; their owner/mode belong to the platform. Directory link counts
    are platform/filesystem dependent and are deliberately NOT asserted.
    """
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} must be a real directory")
    if not strict:
        return
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(
            f"{label} must have exactly 0700 permissions "
            f"(got {oct(stat.S_IMODE(info.st_mode))}); refusing without chmod"
        )


def _audit_no_symlink_ancestors(canonical: Path) -> None:
    """Refuse when ANY absolute prefix component of a canonical path is a link.

    ``canonical`` must already be a realpath-resolved absolute path; this audit
    proves the invariant at call time so an ancestor substitution between
    resolution and open is detected instead of silently followed.
    """
    parts = canonical.parts
    probe = Path(parts[0])
    for part in parts[1:]:
        probe = probe / part
        try:
            info = os.lstat(probe)
        except OSError as exc:
            raise ValueError(f"ancestor {probe} is not statable: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(
                f"ancestor {probe} is a symlink; refusing unsafe private traversal"
            )


_PLATFORM_ALIAS_ROOTS_DARWIN = frozenset({"var", "tmp", "etc"})


class RetainedPrivateChain:
    """Retained O_NOFOLLOW descriptor chain with name-entry continuity proofs.

    Level 0 is the filesystem root (``name=None``). Every later level was
    opened openat-relatively from its retained parent with
    O_DIRECTORY|O_NOFOLLOW under a real supplier or trusted-platform name and
    had its parent name entry compared dev+ino+type against the opened
    descriptor. Each level carries the strictness derived from its pre-audit
    membership: levels at/below the authority root re-run ``_verify_dirinfo``
    on BOTH the retained fstat and the nofollow named stat at every
    revalidation (so a post-open chmod drift refuses), while locator-only
    levels keep real-directory type + identity checks alone. The whole chain
    stays alive so callers can revalidate every name entry immediately before
    release; ``close()`` releases all descriptors deepest-first.
    """

    def __init__(
        self,
        levels: list[tuple[str | None, int]],
        strictness: list[bool] | None = None,
    ) -> None:
        self._levels = levels
        if strictness is None:
            strictness = [False] * len(levels)
        self._strictness = list(strictness)

    def revalidate(self) -> None:
        """Prove each supplied name entry still binds its retained fd."""
        for index in range(1, len(self._levels)):
            name, fd = self._levels[index]
            parent_fd = self._levels[index - 1][1]
            info = os.fstat(fd)
            if self._strictness[index]:
                _verify_dirinfo(
                    info,
                    f"retained private component {name!r}",
                    strict=True,
                )
            try:
                named = os.stat(
                    name, dir_fd=parent_fd, follow_symlinks=False
                )
            except OSError as exc:
                raise ValueError(
                    f"private component {name!r} is no longer statable: {exc}"
                ) from exc
            if (named.st_dev, named.st_ino) != (
                info.st_dev,
                info.st_ino,
            ) or not stat.S_ISDIR(named.st_mode):
                raise ValueError(
                    f"private component {name!r} was substituted after open"
                )
            if self._strictness[index]:
                _verify_dirinfo(
                    named,
                    f"retained private component {name!r} name entry",
                    strict=True,
                )

    @property
    def deepest_fd(self) -> int:
        return self._levels[-1][1]

    def close(self) -> None:
        for _, fd in reversed(self._levels):
            try:
                os.close(fd)
            except OSError:
                pass
        self._levels = []


def _walk_existing_descriptor_chain(
    lexical_directory: Path,
    lexical_authority: Path,
    expected_levels: list[tuple[str | None, tuple[int, int, int, int] | None, bool]],
) -> RetainedPrivateChain:
    """No-create walk: openat O_DIRECTORY|O_NOFOLLOW EVERY supplied component.

    The authority for existence is this retained descriptor chain itself —
    never a full-path lstat/open, which would follow an ancestor symlink
    substituted after the pure lexical audit (O_NOFOLLOW protects only the
    final component). Each component is opened dir_fd-relatively from the
    previous retained fd; BOTH the opened descriptor and its parent nofollow
    name entry are compared against the PRE-AUDIT expected identity from
    ``expected_levels`` — never merely to each other — so a regular directory
    replaced between audit and openat refuses even when the replacement is an
    ordinary current-UID 0700 tree. Strictness follows path membership via
    the snapshot: components strictly ABOVE lexical_authority are locator-only
    real directories; lexical_authority itself and every descendant through
    lexical_directory must additionally keep their audited mode+owner.
    Darwin's trusted first hop /var,/tmp,/etc binds its two named platform
    levels ('private', then the hop) to their /private* pre-audit identities.
    Returns the retained chain (strictness recorded per level); caller closes
    it.
    """
    import errno as _errno

    directory_parts = lexical_directory.parts
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    levels: list[tuple[str | None, int]] = [(None, root_fd)]
    current = Path(directory_parts[0])

    def _bind_opened_level(
        child_fd: int,
        opened_name: str,
        name_dir_fd: int,
        label: str,
        exp_name: str | None,
        exp_info: tuple[int, int, int, int] | None,
        exp_strict: bool,
    ) -> os.stat_result:
        """Bind one opened fd to its pre-audit expectation.

        Ownership protocol: ``child_fd`` is OWNED BY THE CALLER on entry and
        on every exit — this binder NEVER closes it. On success the caller
        appends it to ``levels`` (transferring cleanup to the outer guard);
        on failure the caller's guard closes it exactly once.
        """
        if exp_info is None or exp_name != opened_name:
            raise ValueError(
                f"private component {label} diverges from the audited "
                "component layout"
            )
        try:
            opened_info = os.fstat(child_fd)
            named = os.stat(
                opened_name, dir_fd=name_dir_fd, follow_symlinks=False
            )
        except OSError as exc:
            raise ValueError(
                f"private component {label} is not verifiable: {exc}"
            ) from exc
        expected_key = (exp_info[0], exp_info[1])
        if (opened_info.st_dev, opened_info.st_ino) != expected_key or (
            named.st_dev,
            named.st_ino,
        ) != expected_key or not stat.S_ISDIR(named.st_mode):
            raise ValueError(
                f"private component {label} was replaced after the "
                "lexical audit"
            )
        if exp_strict:
            expected_meta = (stat.S_IMODE(exp_info[2]), exp_info[3])
            for probed in (opened_info, named):
                if (stat.S_IMODE(probed.st_mode), probed.st_uid) != expected_meta:
                    raise ValueError(
                        f"private ancestor {label} changed permissions or "
                        "owner after the lexical audit"
                    )
            _verify_dirinfo(opened_info, f"private ancestor {label}", strict=True)
        return opened_info

    try:
        level_index = 0
        for position, part in enumerate(directory_parts[1:], start=1):
            candidate = current / part
            if level_index + 1 >= len(expected_levels):
                # The pure audit ended early: this component was absent when
                # audited. Nothing may be created on the no-create seam.
                raise ValueError(
                    f"private path {lexical_directory} is missing "
                    f"component {part!r}; refusing to create"
                )
            known_hop_position = (
                sys.platform == "darwin"
                and position == 1
                and part in _PLATFORM_ALIAS_ROOTS_DARWIN
            )
            if known_hop_position:
                try:
                    target = os.readlink(candidate)
                except OSError:
                    target = None
                if isinstance(target, str):
                    known_targets = {
                        "private/" + part,
                        "/private/" + part,
                    }
                    if target not in known_targets:
                        raise ValueError(
                            f"supplier ancestor {candidate} is a symlink to "
                            f"{target}; only the trusted platform mount "
                            f"/private/{part} may alias this position"
                        )
                    level_index += 1
                    private_exp = expected_levels[level_index]
                    if level_index + 1 >= len(expected_levels):
                        raise ValueError(
                            "trusted platform mount diverges from the "
                            "audited component layout"
                        )
                    private_fd = -1
                    hop_fd = -1
                    try:
                        try:
                            private_fd = os.open(
                                "private",
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=root_fd,
                            )
                        except OSError as exc:
                            raise ValueError(
                                f"trusted platform mount /private could not "
                                f"be opened safely: {exc}"
                            ) from exc
                        _bind_opened_level(
                            private_fd,
                            "private",
                            root_fd,
                            "trusted platform mount /private",
                            *private_exp,
                        )
                        level_index += 1
                        hop_exp = expected_levels[level_index]
                        try:
                            hop_fd = os.open(
                                part,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=private_fd,
                            )
                        except OSError as exc:
                            raise ValueError(
                                f"trusted platform mount /private/{part} "
                                f"could not be opened safely: {exc}"
                            ) from exc
                        _bind_opened_level(
                            hop_fd,
                            part,
                            private_fd,
                            candidate,
                            *hop_exp,
                        )
                    except BaseException:
                        # Ownership sentinels: each fd is closed here exactly
                        # once iff it was opened and never appended to
                        # ``levels`` (append transfers cleanup ownership to
                        # the outer guard). The binder never closes, so no
                        # double-close is possible.
                        for owned in (hop_fd, private_fd):
                            if owned >= 0:
                                try:
                                    os.close(owned)
                                except OSError:
                                    pass
                        raise
                    levels.append(("private", private_fd))
                    levels.append((part, hop_fd))
                    current = candidate
                    continue
            level_index += 1
            exp_name, exp_info, exp_strict = expected_levels[level_index]
            try:
                child_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=levels[-1][1],
                )
            except FileNotFoundError as exc:
                raise ValueError(
                    f"private path {lexical_directory} is missing "
                    f"component {part!r}; refusing to create"
                ) from exc
            except NotADirectoryError as exc:
                try:
                    entry = os.lstat(part, dir_fd=levels[-1][1])
                except OSError:
                    entry = None
                if entry is not None and stat.S_ISLNK(entry.st_mode):
                    raise ValueError(
                        f"supplier ancestor {candidate} is a symlink; "
                        "refusing unsafe private traversal"
                    ) from exc
                raise ValueError(
                    f"private ancestor {candidate} must be a real directory"
                ) from exc
            except OSError as exc:
                if exc.errno == _errno.ELOOP:
                    raise ValueError(
                        f"supplier ancestor {candidate} is a symlink; "
                        "refusing unsafe private traversal"
                    ) from exc
                raise ValueError(
                    f"private ancestor {candidate} could not be opened "
                    f"safely: {exc}"
                ) from exc
            try:
                _bind_opened_level(
                    child_fd,
                    part,
                    levels[-1][1],
                    candidate,
                    exp_name,
                    exp_info,
                    exp_strict,
                )
            except BaseException:
                try:
                    os.close(child_fd)
                except OSError:
                    pass
                raise
            levels.append((part, child_fd))
            current = candidate
        if len(expected_levels) != len(levels):
            raise ValueError(
                "private path diverges from the audited component layout"
            )
        return RetainedPrivateChain(
            levels, [entry[2] for entry in expected_levels]
        )
    except BaseException:
        for _, fd in reversed(levels):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _audit_lexical_components_pure(
    lexical: Path,
    authority_root_position: int | None = None,
) -> list[tuple[str | None, tuple[int, int, int, int] | None, bool]]:
    """Sole authoritative pure-lstat component audit AND identity capture.

    Walks every supplied component in lexical order using os.lstat ONLY —
    before any realpath/resolve/openat could erase alias evidence — and
    returns the exact ordered per-level snapshot consumed directly by the
    no-create descriptor walk: level 0 is the filesystem-root sentinel;
    every further level carries the component name opened from its retained
    parent, its PRE-AUDIT identity ``(st_dev, st_ino, st_mode, st_uid)``, and
    its strictness. There is deliberately NO second filesystem pass: any
    consumer needing expectations MUST use this snapshot, or a replacement
    between an earlier discarded audit and a later resnapshot would be
    accepted.

    A symlink component refuses immediately as supplier-controlled aliasing
    — direct root alias or ancestor alias alike — even when its target is an
    otherwise valid private directory. Sole tolerance: the known Darwin
    first-hop mount aliases (``/var``, ``/tmp``, ``/etc`` into
    ``/private/*``) at position 1; their link target is validated and BOTH
    platform levels are captured explicitly against their ``/private``
    identities. When ``authority_root_position`` is given (no-create seam),
    the authority root and every descendant must be current-UID exact-0700
    and strictly-above components stay locator-only real directories. With
    the default ``None`` (ordinary create=True constructor flows) no
    strict/mode enforcement happens here — those flows keep their existing
    audit semantics and enforce strictness during their own creation walk.
    An absent tail returns the partial snapshot; only after this audit
    succeeds may the caller invoke realpath or open anything.
    """
    parts = lexical.parts
    probe = Path(parts[0])
    snapshot: list[tuple[str | None, tuple[int, int, int, int] | None, bool]] = [
        (None, None, False)
    ]
    for position, part in enumerate(parts[1:], start=1):
        candidate = probe / part
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            # Absent components cannot alias anything; creation flows make
            # tails exist only after this audit. Nothing further can be a
            # supplier symlink until it is created, and creation is
            # descriptor-relative under retained parents. The partial
            # snapshot lets the no-create walk report the missing component
            # precisely.
            return snapshot
        except OSError as exc:
            raise ValueError(
                f"supplied ancestor {candidate} is not statable: {exc}"
            ) from exc
        known_platform_hop = (
            sys.platform == "darwin"
            and position == 1
            and part in _PLATFORM_ALIAS_ROOTS_DARWIN
        )
        if stat.S_ISLNK(info.st_mode):
            if not known_platform_hop:
                raise ValueError(
                    f"supplied ancestor {candidate} is a symlink; "
                    "refusing unsafe private traversal"
                )
            target = None
            try:
                target = os.readlink(candidate)
            except OSError:
                pass
            known_targets = {"private/" + part, "/private/" + part}
            if not isinstance(target, str) or target not in known_targets:
                raise ValueError(
                    f"supplier ancestor {candidate} is a symlink to "
                    f"{target}; only the trusted platform mount "
                    f"/private/{part} may alias this position"
                )
            private_info = os.lstat("/private")
            _verify_dirinfo(
                private_info, "trusted platform mount /private", strict=False
            )
            snapshot.append(
                (
                    "private",
                    (
                        private_info.st_dev,
                        private_info.st_ino,
                        private_info.st_mode,
                        private_info.st_uid,
                    ),
                    False,
                )
            )
            hop_info = os.lstat("/private/" + part)
            _verify_dirinfo(
                hop_info,
                f"trusted platform mount /private/{part}",
                strict=False,
            )
            snapshot.append(
                (
                    part,
                    (
                        hop_info.st_dev,
                        hop_info.st_ino,
                        hop_info.st_mode,
                        hop_info.st_uid,
                    ),
                    False,
                )
            )
            probe = candidate
            continue
        strict_here = (
            authority_root_position is not None
            and position >= authority_root_position
        )
        _verify_dirinfo(info, f"private ancestor {candidate}", strict=strict_here)
        snapshot.append(
            (
                part,
                (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_uid,
                ),
                strict_here,
            )
        )
        probe = candidate
    return snapshot


def _walk_from_filesystem_root(
    directory: Path,
    *,
    authority_root: Path,
    create: bool = True,
) -> Union[int, "RetainedPrivateChain"]:
    """Retained descriptor-walk with strict lexical-path symlink refusal.

    Both arguments are treated as LEXICAL absolute paths. Because callers pass
    ``ProductPaths.resolve``-canonical spellings (platform aliases such as the
    macOS ``/var`` link are resolved once at that trusted boundary), any
    remaining difference between ``os.path.realpath(lexical)`` and the lexical
    path proves an attacker-controlled descendant symlink and REFUSES even
    when the symlink target is a current-UID 0700 directory. Existing absolute
    prefix components are then audited so no component anywhere above the
    deepest existing ancestor is a link; the anchor is opened once with
    O_DIRECTORY|O_NOFOLLOW while its dev+ino identity is pinned around the
    open. Every step below uses pure *at() semantics against retained
    descriptors. Components at or below ``authority_root`` must be real
    current-UID exact-0700 directories; strictly-above components need only be
    real directories. With ``create=True`` (constructors) missing components
    at/below the authority root are created descriptor-relatively under the
    cooperating umask; with ``create=False`` (no-create verification seams)
    ANY missing component refuses and nothing is ever mutated. Returns the
    retained final directory descriptor (caller closes it).
    """
    import errno as _errno

    lexical_directory = Path(os.path.abspath(directory))
    lexical_authority = Path(os.path.abspath(authority_root))
    if not create:
        # No-create verification uses ONLY the retained descriptor chain;
        # full-path lstat/open would follow an ancestor swapped after the
        # audit (O_NOFOLLOW guards the final component alone). The
        # filesystem-free containment check may precede; the SINGLE pure
        # lstat audit below is simultaneously the symlink/type/strict audit
        # AND the expected-identity capture — there is no earlier discarded
        # filesystem pass and no later resnapshot window.
        try:
            lexical_directory.relative_to(lexical_authority)
        except ValueError as exc:
            raise ValueError(
                f"target {lexical_directory} is not at or below the private authority root "
                f"{lexical_authority}"
            ) from exc
        expected_levels = _audit_lexical_components_pure(
            lexical_directory,
            authority_root_position=len(lexical_authority.parts) - 1,
        )
        return _walk_existing_descriptor_chain(
            lexical_directory, lexical_authority, expected_levels
        )
    # Pure lstat audit FIRST: supplier aliasing refuses before realpath is
    # ever consulted (spy-testable ordering guarantee). Ordinary create=True
    # constructor flows keep their existing audit path unchanged.
    _audit_lexical_components_pure(lexical_directory)
    _audit_lexical_components_pure(lexical_authority)
    try:
        lexical_directory.relative_to(lexical_authority)
    except ValueError as exc:
        raise ValueError(
            f"target {lexical_directory} is not at or below the private authority root "
            f"{lexical_authority}"
        ) from exc
    # Deepest existing ancestor via lstat (never following links).
    missing: list[str] = []
    probe = lexical_directory
    while True:
        try:
            info = os.lstat(probe)
        except OSError as exc:
            if exc.errno != _errno.ENOENT:
                raise ValueError(f"private ancestor {probe} is not statable: {exc}") from exc
            missing.append(probe.name)
            parent = probe.parent
            if parent == probe:
                raise ValueError(f"private root {probe} is absent") from exc
            probe = parent
            continue
        strict_anchor = probe == lexical_authority or lexical_authority in probe.parents
        _verify_dirinfo(info, f"private ancestor {probe}", strict=strict_anchor)
        break
    if missing and not create:
        raise ValueError(
            f"private path {lexical_directory} is missing "
            f"{len(missing)} component(s); refusing to create"
        )
    # Every EXISTING absolute prefix of the resolved anchor must be a real
    # directory, never a symlink; absent components below the anchor are
    # created descriptor-relatively afterwards (create=True only).
    _audit_no_symlink_ancestors(Path(os.path.realpath(probe)))
    anchor_identity = (info.st_dev, info.st_ino)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(probe, flags)
    except OSError as exc:
        raise ValueError(f"private ancestor {probe} could not be opened safely: {exc}") from exc
    try:
        reopened = os.fstat(fd)
        if (reopened.st_dev, reopened.st_ino) != anchor_identity:
            raise ValueError(
                f"private ancestor {probe} was substituted during open"
            )
        current = probe
        for part in reversed(missing):
            child_strict = True  # every created component is inside authority
            try:
                child_info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except OSError as exc:
                if exc.errno != _errno.ENOENT:
                    raise ValueError(
                        f"private component {current / part} is not verifiable: {exc}"
                    ) from exc
                with owner_private_umask():
                    os.mkdir(part, 0o700, dir_fd=fd)
                child_info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            _verify_dirinfo(
                child_info, f"private component {current / part}", strict=child_strict
            )
            child_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child_fd
            current = current / part
        return fd
    except BaseException:
        os.close(fd)
        raise


def _normal_absolute_private_spelling(textual: str) -> str:
    """Validate the ORIGINAL operator spelling before any normalization.

    ``os.path.abspath``/``normpath`` erase ``..`` (and redundant separators)
    lexically, so a spelling like ``/base/alias/../root`` would silently drop
    the symlink component ``alias`` and never be audited. This inspection
    runs on the raw supplied text BEFORE canonicalization: parent-traversal
    components (``..``), self components (``.``), and empty components
    (duplicate/trailing separators) are non-normal spellings the no-create
    seam refuses outright. A relative spelling is made absolute by PURE
    textual concatenation with the current directory — no component is ever
    erased or followed — and the joined form must then pass the same
    normality rules; anything else fails closed.
    """
    if not textual:
        raise ValueError("supplied private data root spelling is empty")
    candidate = textual
    if not candidate.startswith("/"):
        candidate = os.getcwd() + "/" + candidate
    segments = candidate.split("/")
    for segment in segments[1:]:
        if segment == "..":
            raise ValueError(
                f"supplied private data root {textual!r} contains a parent "
                "traversal component '..'; refusing non-normal private "
                "spelling"
            )
        if segment == ".":
            raise ValueError(
                f"supplied private data root {textual!r} contains a "
                "self component '.'; refusing non-normal private spelling"
            )
        if segment == "":
            raise ValueError(
                f"supplied private data root {textual!r} contains an empty "
                "component (duplicate or trailing separator); refusing "
                "non-normal private spelling"
            )
    return candidate


def open_existing_private_data_root(
    override: str | Path | None = None,
) -> "RetainedPrivateChain":
    """No-create retained verification of the EXISTING private data root.

    Inspects the RAW supplied override or ``MARKET_ALIGNER_DATA_HOME`` text
    lexically BEFORE any Path construction / expanduser-normpath / abspath /
    resolve could erase alias or traversal evidence: parent-traversal,
    self, and empty components refuse outright and every remaining component
    is audited as supplied; refuses when any supplier-controlled component or
    ancestor is a symlink, when the root is missing, not a real directory,
    not owned by the current user, or not exactly 0700. String overrides and
    environment values are received EXACTLY as supplied (only a leading
    ``~`` is expanded textually — never normpath/abspath/resolved); the
    canonical default spelling is used only when neither source supplies a
    value. A ``Path`` override cannot carry recoverable raw-string evidence:
    pathlib normalizes at construction time on the CALLER side, so such
    input is audited as-received but its pre-Path spelling is outside what
    this seam can prove. The canonical no-create seam returns the retained
    descriptor CHAIN (with revalidate/close) built by pure dir_fd/openat
    O_DIRECTORY|O_NOFOLLOW walking with per-level name-entry continuity
    proofs — never a whole-path open. Performs ZERO mutation (no mkdir, no
    chmod). Ordinary constructors keep using
    ``ProductPaths.resolve(...).ensure()`` unchanged.
    """
    if override is not None:
        raw = os.fspath(override)
    else:
        # Presence is decisive: a PRESENT-but-empty variable must reach the
        # spelling gate as empty text and refuse there — the canonical
        # default is selected ONLY when the variable is absent.
        configured = os.environ.get(DATA_HOME_ENV)
        if configured is not None:
            raw = configured
        else:
            raw = os.path.join(
                os.path.expanduser("~"),
                ".local",
                "share",
                "market-aligner",
            )
    lexical = Path(
        _normal_absolute_private_spelling(os.path.expanduser(raw))
    )
    return _walk_from_filesystem_root(
        lexical,
        authority_root=lexical,
        create=False,
    )


def ensure_private_directory(path: Path, *, authority_root: Path | None = None) -> None:
    """Descriptor-walk/create every component of an owner-private 0700 dir.

    The walk starts at the retained filesystem-root descriptor and proceeds
    with openat/mkdirat semantics (O_NOFOLLOW everywhere); a symlink in ANY
    ancestor refuses rather than being followed. Components at or below the
    bounded private authority root (default: the direct parent) must be real
    current-UID exact-0700 directories; unsafe or substituted ancestors refuse.
    Directory link counts are intentionally not asserted.
    """
    effective_authority = (
        Path(os.path.abspath(authority_root)) if authority_root else Path(os.path.abspath(path.parent))
    )
    parent_fd = _walk_from_filesystem_root(path.parent, authority_root=effective_authority)
    try:
        name = os.path.basename(os.path.abspath(path))
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            import errno as _errno

            if exc.errno != _errno.ENOENT:
                raise ValueError(f"private directory {path} is not statable: {exc}") from exc
            with owner_private_umask():
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _verify_dirinfo(info, f"private directory {path}", strict=True)
    finally:
        os.close(parent_fd)


def verify_private_file(path: Path, *, label: str) -> os.stat_result:
    """Require a current-UID regular single-link 0600 file; refuse otherwise."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} {path} is not statable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} {path} must be a regular file")
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} {path} must be owned by the current user")
    if info.st_nlink != 1:
        raise ValueError(f"{label} {path} must have exactly one link (nlink={info.st_nlink})")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(
            f"{label} {path} must have exactly 0600 permissions "
            f"(got {oct(stat.S_IMODE(info.st_mode))}); refusing without chmod"
        )
    return info


def create_private_database_file(path: Path, *, authority_root: Path | None = None) -> None:
    """Descriptor-walk parents at 0700 and exclusively create the leaf at 0600.

    Every existing component is verified (real current-UID exact-0700
    directory; regular current-UID single-link 0600 leaf) and refuses rather
    than being silently chmodded. New components are created descriptor-
    relatively under the cooperating owner-private umask with O_NOFOLLOW /
    O_EXCL so symlinks cannot substitute any step. A freshly created leaf is
    fstat-verified (regular/current-UID/single-link/0600) and its parent name
    entry must match the retained leaf dev+ino before returning.
    """
    parent = path.parent
    effective_authority = (
        Path(os.path.abspath(authority_root)) if authority_root else Path(os.path.abspath(parent))
    )
    parent_fd = _walk_from_filesystem_root(parent, authority_root=effective_authority)
    try:
        name = os.path.basename(os.path.abspath(path))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            descriptor = None
        except OSError as exc:
            import errno as _errno

            if exc.errno == _errno.EEXIST:
                descriptor = None
            else:
                raise ValueError(f"database {path} could not be created: {exc}") from exc
        if descriptor is not None:
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f"database {path} did not create as a regular file")
                if info.st_uid != os.getuid():
                    raise ValueError(f"database {path} must be owned by the current user")
                if info.st_nlink != 1:
                    raise ValueError(
                        f"database {path} must have exactly one link (nlink={info.st_nlink})"
                    )
                if stat.S_IMODE(info.st_mode) != 0o600:
                    os.fchmod(descriptor, 0o600)
                    info = os.fstat(descriptor)
                    if stat.S_IMODE(info.st_mode) != 0o600:
                        raise ValueError(
                            f"database {path} could not take exact 0600 permissions"
                        )
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError(
                        f"database {path} leaf was substituted during creation"
                    )
            finally:
                os.close(descriptor)
            return
        # Existing leaf: verify strictly via the retained parent, never chmod.
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"database {path} must be a regular file")
        if info.st_uid != os.getuid():
            raise ValueError(f"database {path} must be owned by the current user")
        if info.st_nlink != 1:
            raise ValueError(
                f"database {path} must have exactly one link (nlink={info.st_nlink})"
            )
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError(
                f"database {path} must have exactly 0600 permissions "
                f"(got {oct(stat.S_IMODE(info.st_mode))}); refusing without chmod"
            )
    finally:
        os.close(parent_fd)
