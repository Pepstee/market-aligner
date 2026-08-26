"""FIT-001 Stage B: coherent profile/evidence generation ownership.

Authority: docs/processing/FIT-001_PROCESS_ONE_CONTRACT.md
(SHA-256 1f9b2f1f7b8196023a1fbbdd9f0d52f22151a05cb55bf4b53e41d4e277a96c42),
sections 4, 6, and 21. Frozen implementation under test:
src/market_aligner/profiler/store.py
(SHA-256 ab00c8be9013792cf8353244988a9b65483f281229e3210f64a7ef71ccc55aa5).

Every test drives the real public seams (ProfileStore / open_existing /
coherent_snapshot / save) or the private deterministic fault seams the
implementation exposes for this acceptance campaign. No provider, network,
browser, JAA, release, submission, or Git action exists anywhere here.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import errno
import fcntl
import hashlib
import inspect
import json
import os
import pathlib
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import typing
import unittest
from dataclasses import asdict

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = str(PROJECT_ROOT / "src")

from market_aligner import config as config_module
from market_aligner import processing as processing_module
from market_aligner.config import ProductPaths
from market_aligner.profiler import store as store_module
from market_aligner.profiler.schema import (
    CandidateProfile,
    EvidenceItem,
    TrackProfile,
)
from market_aligner.profiler.store import (
    EVIDENCE_NAME,
    MANIFEST_NAME,
    MANIFEST_SCHEMA,
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_ROWS,
    MAX_MANIFEST_BYTES,
    MAX_PROFILE_BYTES,
    PROFILE_NAME,
    CoherentProfileSnapshot,
    DurableInProgressSaveFailed,
    ProfileGenerationOutcomeUnknown,
    ProfileStore,
)
from market_aligner.research import store as research_store_module

PID = "prf_" + "0" * 32
OTHER_PID = "prf_" + "1" * 32

# Accepted publication boundaries (contract §6 exact order).
STEP1_TEMPSYNC = "after_manifest_temp_fsync"
BOUNDARY_INITIAL_RENAME = "after_initial_rename"
BOUNDARY_INITIAL_DIRFSYNC = "after_initial_dirfsync"
BOUNDARY_STEP1_BARRIER = "after_step1_barrier"
BOUNDARY_LEAF_TEMPSYNC = "after_leaf_temp_fsync"
BOUNDARY_LEAF_RENAMES = "after_leaf_renames"
BOUNDARY_CONTENT_BARRIER = "after_content_barrier"
BOUNDARY_CONTENT_VERIFY = "after_content_verify"
BOUNDARY_COMMITTED_TEMPSYNC = "after_committed_temp_fsync"
BOUNDARY_COMMITTED_RENAME = "after_committed_rename"
BOUNDARY_FINAL_DIRFSYNC = "after_final_dirfsync"
# Six rollback hooks paired with after_committed_rename.
ROLLBACK_HOOKS = (
    "rollback_temp_create",
    "rollback_temp_write",
    "rollback_temp_fsync",
    "rollback_rename",
    "rollback_dirfsync",
    "rollback_revalidate",
)


def _profile(version: str = "v1", pid: str = PID) -> CandidateProfile:
    return CandidateProfile(
        profile_id=pid,
        version=version,
        tracks={
            "automation": TrackProfile(
                interest=8.0,
                demonstrated_skill=7.0,
                confidence=0.8,
                market_readiness=6.0,
                rationale="Bound to a verified project.",
            )
        },
    )


def _evidence(eid: str = "ev1", claim: str = "Shipped X.") -> EvidenceItem:
    return EvidenceItem(
        evidence_id=eid,
        kind="project",
        claim=claim,
        source_ref="repo/example",
        status="verified",
        confidence=0.9,
    )


def _row(item: EvidenceItem) -> str:
    return json.dumps(asdict(item), ensure_ascii=False, sort_keys=True)


def _new_store(tmp: str) -> ProfileStore:
    """Ordinary write-owning constructor (allowed for fixture owners)."""
    return ProfileStore(tmp)


def _write_leaf(store: ProfileStore, name: str, payload: bytes) -> None:
    """Directly (re)place one leaf with exact 0600 single-link semantics."""
    directory = store.directory(PID)
    temporary = directory / f".inject-{name}"
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    view = memoryview(payload)
    while view:
        view = view[os.write(fd, view) :]
    os.close(fd)
    os.replace(temporary, directory / name)


def _drop_manifest(store: ProfileStore) -> None:
    """Remove generation.json so the pair becomes explicitly legacy."""
    os.unlink(store.directory(PID) / MANIFEST_NAME)


def _tree_digest(
    root: pathlib.Path, *, include_dir_mtime: bool = True
) -> list:
    """Order-stable digest of every name/identity/byte/mtime under root.

    The exact default binds st_mtime_ns for directories, regular files, and
    other entries alike. ``include_dir_mtime=False`` is a NON-EXACT
    canonical-entry comparison reserved for the single post-temp fault
    assertion where mutation had already begun and private temp
    create/unlink legitimately churned a directory mtime.
    """
    entries: list = []
    if not root.exists():
        return entries

    def ident(info: os.stat_result) -> tuple:
        base = (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        )
        return base + (info.st_mtime_ns,)

    for current, dirs, files in os.walk(root):
        dirs.sort()
        rel = pathlib.Path(current).relative_to(root)
        dir_info = os.lstat(current)
        if include_dir_mtime:
            entries.append((str(rel), "dir", ident(dir_info)))
        else:
            # NON-EXACT: directory mtime dropped for this comparison only.
            entries.append((str(rel), "dir", ident(dir_info)[:-1]))
        for name in sorted(files):
            path = pathlib.Path(current) / name
            finfo = os.lstat(path)
            if stat.S_ISREG(finfo.st_mode):
                entries.append(
                    (
                        str(rel / name),
                        "file",
                        ident(finfo)
                        + (hashlib.sha256(path.read_bytes()).hexdigest(),),
                    )
                )
            else:
                entries.append((str(rel / name), "other", ident(finfo)))
    entries.sort()
    return entries


def _fd_count() -> int:
    return len(os.listdir("/dev/fd"))


def _manifest_bytes(directory: pathlib.Path) -> bytes:
    return (directory / MANIFEST_NAME).read_bytes()


def _parse_manifest(data: bytes) -> dict:
    parsed = json.loads(data.decode("utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def _canonical(doc: dict) -> bytes:
    return (
        json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _expected_manifest(state: str, profile_sha: str, evidence_sha: str,
                       profile_id: str = PID) -> bytes:
    five = {
        "schema_version": MANIFEST_SCHEMA,
        "state": state,
        "profile_id": profile_id,
        "profile_file_sha256": profile_sha,
        "evidence_file_sha256": evidence_sha,
    }
    canonical_five = json.dumps(
        five, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    six = dict(five)
    six["generation_sha256"] = hashlib.sha256(canonical_five.encode()).hexdigest()
    return _canonical(six)


class TempRootTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        store_module._clear_faults()
        self.addCleanup(store_module._clear_faults)


# ---------------------------------------------------------------------------
# Public no-write seam: open_existing (contract §6; §21 no-write boundaries)
# ---------------------------------------------------------------------------


class OpenExistingSeamTests(TempRootTestCase):
    def test_open_existing_is_public_classmethod_and_write_free(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [_evidence()])
        digest = _tree_digest(pathlib.Path(self.root))
        fitted = ProfileStore.open_existing(self.root)
        self.assertIsInstance(fitted, ProfileStore)
        self.assertIsInstance(
            inspect.getattr_static(ProfileStore, "open_existing"), classmethod
        )
        self.assertEqual(
            str(ProductPaths.resolve(self.root).root), str(fitted.paths.root)
        )
        self.assertEqual(digest, _tree_digest(pathlib.Path(self.root)))

    def test_missing_data_home_refuses_without_creating_anything(self) -> None:
        absent_root = pathlib.Path(self.root) / "does-not-exist"
        with self.assertRaises((ValueError, FileNotFoundError, OSError)):
            ProfileStore.open_existing(str(absent_root))
        self.assertFalse(absent_root.exists())

    def test_missing_profiles_level_refuses_without_creating_it(self) -> None:
        home = pathlib.Path(self.root) / "home"
        home.mkdir(mode=0o700)
        with self.assertRaises((ValueError, FileNotFoundError, OSError)):
            ProfileStore.open_existing(str(home))
        self.assertFalse((home / "profiles").exists())
        self.assertEqual(0o700, stat.S_IMODE(home.stat().st_mode))

    def test_unsafe_data_home_mode_refuses_without_chmod(self) -> None:
        home = pathlib.Path(self.root) / "home"
        home.mkdir(mode=0o700)
        (home / "profiles").mkdir(mode=0o700)
        os.chmod(home, 0o755)
        before = stat.S_IMODE(home.stat().st_mode)
        try:
            with self.assertRaises(ValueError):
                ProfileStore.open_existing(str(home))
            self.assertEqual(before, stat.S_IMODE(home.stat().st_mode))
        finally:
            os.chmod(home, 0o700)

    def test_symlinked_data_home_refused(self) -> None:
        real = pathlib.Path(self.root) / "real-home"
        real.mkdir(mode=0o700)
        _new_store(str(real)).save(_profile(), [_evidence()])
        alias = pathlib.Path(self.root) / "alias-home"
        os.symlink(real, alias)
        before = _tree_digest(alias)
        with self.assertRaises(ValueError) as caught:
            ProfileStore.open_existing(str(alias))
        self.assertIn("symlink", str(caught.exception))
        self.assertEqual(before, _tree_digest(alias))
        # The otherwise-valid target stays fully loadable through its
        # canonical spelling; only the alias is refused.
        fitted = ProfileStore.open_existing(str(real))
        snapshot = fitted.snapshot(PID)
        try:
            self.assertEqual("v1", snapshot.profile.version)
        finally:
            snapshot.close()

    def test_symlinked_data_home_via_env_spelling_refused(self) -> None:
        real = pathlib.Path(self.root) / "real-home-env"
        real.mkdir(mode=0o700)
        _new_store(str(real)).save(_profile(), [])
        alias = pathlib.Path(self.root) / "alias-home-env"
        os.symlink(real, alias)
        previous = os.environ.get("MARKET_ALIGNER_DATA_HOME")
        os.environ["MARKET_ALIGNER_DATA_HOME"] = str(alias)
        try:
            with self.assertRaises(ValueError) as caught:
                ProfileStore.open_existing()
            self.assertIn("symlink", str(caught.exception))
        finally:
            if previous is None:
                del os.environ["MARKET_ALIGNER_DATA_HOME"]
            else:
                os.environ["MARKET_ALIGNER_DATA_HOME"] = previous

    def test_symlinked_data_home_ancestor_refused_with_valid_target(self) -> None:
        parent = pathlib.Path(self.root) / "outer"
        real = parent / "real-inner"
        real.mkdir(parents=True, mode=0o700)
        (real / "profiles").mkdir(mode=0o700)
        alias = parent / "alias-inner"
        os.symlink(real, alias)
        before = _tree_digest(parent)
        with self.assertRaises(ValueError) as caught:
            ProfileStore.open_existing(str(alias))
        self.assertIn("symlink", str(caught.exception))
        self.assertEqual(before, _tree_digest(parent))

    def test_alias_refusal_precedes_productpaths_resolve(self) -> None:
        import unittest.mock as mock

        real = pathlib.Path(self.root) / "order-real"
        real.mkdir(mode=0o700)
        _new_store(str(real)).save(_profile(), [])
        direct = pathlib.Path(self.root) / "order-direct"
        os.symlink(real, direct)
        outer = pathlib.Path(self.root) / "order-outer"
        outer.mkdir(mode=0o700)
        inner = outer / "order-inner"
        inner.mkdir(mode=0o700)
        (inner / "profiles").mkdir(mode=0o700)
        ancestor = outer / "order-alias"
        os.symlink(inner, ancestor)
        with mock.patch.object(
            store_module.ProductPaths,
            "resolve",
            side_effect=AssertionError("ProductPaths.resolve reached"),
        ):
            for spelling in (str(direct), str(ancestor)):
                with self.subTest(spelling=spelling):
                    with self.assertRaises(ValueError) as caught:
                        ProfileStore.open_existing(spelling)
                    self.assertIn("symlink", str(caught.exception))
            previous = os.environ.get("MARKET_ALIGNER_DATA_HOME")
            os.environ["MARKET_ALIGNER_DATA_HOME"] = str(direct)
            try:
                with self.assertRaises(ValueError) as caught:
                    ProfileStore.open_existing()
                self.assertIn("symlink", str(caught.exception))
            finally:
                if previous is None:
                    del os.environ["MARKET_ALIGNER_DATA_HOME"]
                else:
                    os.environ["MARKET_ALIGNER_DATA_HOME"] = previous

    def test_alias_refusal_never_reaches_realpath(self) -> None:
        import unittest.mock as mock

        real = pathlib.Path(self.root) / "rp-real"
        real.mkdir(mode=0o700)
        _new_store(str(real)).save(_profile(), [])
        direct = pathlib.Path(self.root) / "rp-direct"
        os.symlink(real, direct)
        outer = pathlib.Path(self.root) / "rp-outer"
        outer.mkdir(mode=0o700)
        inner = outer / "rp-inner"
        inner.mkdir(mode=0o700)
        (inner / "profiles").mkdir(mode=0o700)
        ancestor = outer / "rp-alias"
        os.symlink(inner, ancestor)
        reached: list = []

        def spy_realpath(path):
            reached.append(path)
            raise AssertionError("realpath reached before lexical audit")

        with mock.patch("os.path.realpath", spy_realpath):
            for spelling in (str(direct), str(ancestor)):
                with self.subTest(spelling=spelling):
                    with self.assertRaises(ValueError) as caught:
                        ProfileStore.open_existing(spelling)
                    self.assertIn("symlink", str(caught.exception))
        self.assertEqual([], reached)

    def test_valid_input_resolves_only_after_seam_success(self) -> None:
        import unittest.mock as mock

        real = pathlib.Path(self.root) / "seq-real"
        real.mkdir(mode=0o700)
        _new_store(str(real)).save(_profile(), [])
        order: list[str] = []
        real_seam = store_module.open_existing_private_data_root
        real_resolve = store_module.ProductPaths.resolve

        def seam_recorder(arg):
            order.append("seam")
            return real_seam(arg)

        def resolve_recorder(arg=None):
            order.append("resolve")
            return real_resolve(arg)

        with mock.patch.object(
            store_module, "open_existing_private_data_root", seam_recorder
        ), mock.patch.object(
            store_module.ProductPaths, "resolve", resolve_recorder
        ):
            fitted = ProfileStore.open_existing(str(real))
        self.assertEqual(["seam", "resolve"], order)
        snapshot = fitted.snapshot(PID)
        try:
            self.assertEqual("v1", snapshot.profile.version)
        finally:
            snapshot.close()

    def test_true_descendant_beneath_symlinked_ancestor_refuses(self) -> None:
        import unittest.mock as mock

        outer = pathlib.Path(self.root) / "ta-outer"
        base = outer / "ta-base"
        child = base / "ta-child"
        (child / "profiles").mkdir(parents=True)
        os.chmod(base, 0o700)
        os.chmod(child, 0o700)
        os.chmod(child / "profiles", 0o700)
        alias = outer / "ta-base-alias"
        os.symlink(base, alias)
        before = _tree_digest(outer)
        with mock.patch.object(
            store_module.ProductPaths,
            "resolve",
            side_effect=AssertionError("ProductPaths.resolve reached"),
        ), mock.patch(
            "os.path.realpath",
            side_effect=AssertionError("realpath reached"),
        ):
            with self.assertRaises(ValueError) as caught:
                ProfileStore.open_existing(str(alias / "ta-child"))
        self.assertIn("symlink", str(caught.exception))
        self.assertEqual(before, _tree_digest(outer))

    def test_strictness_is_authority_membership_not_prefix_depth(self) -> None:
        # Above-authority components are locator-only real directories; the
        # authority root itself and everything below it must be 0700.
        base = pathlib.Path(self.root) / "strict-base"
        auth = base / "auth"
        root = auth / "root"
        (root / "profiles").mkdir(parents=True)
        os.chmod(base, 0o755)
        os.chmod(auth, 0o700)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        chain = config_module._walk_from_filesystem_root(
            pathlib.Path(root),
            authority_root=pathlib.Path(auth),
            create=False,
        )
        try:
            info = os.fstat(chain.deepest_fd)
            self.assertEqual(os.stat(root).st_ino, info.st_ino)
            chain.revalidate()
        finally:
            chain.close()
        with self.assertRaises(ValueError):
            bad = pathlib.Path(self.root) / "strict-bad"
            bad.mkdir(mode=0o755)
            deep = bad / "deep"
            deep.mkdir(mode=0o700)
            try:
                config_module._walk_from_filesystem_root(
                    deep, authority_root=bad, create=False
                )
            finally:
                deep.rmdir()
                bad.rmdir()

    def test_swap_after_audit_before_nonleaf_openat_refuses(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "swap-a"
        auth = base / "auth"
        root = auth / "root"
        (root / "profiles").mkdir(parents=True)
        os.chmod(base, 0o700)
        os.chmod(auth, 0o700)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        real_open = os.open
        state = {"swapped": False}

        def swapping_open(path, flags, mode=0o777, dir_fd=None):
            if (
                not state["swapped"]
                and dir_fd is not None
                and path == "auth"
                and flags & os.O_NOFOLLOW
                and flags & os.O_DIRECTORY
            ):
                state["swapped"] = True
                os.rename(str(auth), str(base / "auth-old"))
                os.symlink(str(base / "auth-old"), str(auth))
            return real_open(path, flags, mode, dir_fd=dir_fd)

        moved = False
        try:
            with mock.patch.object(config_module.os, "open", swapping_open), \
                    mock.patch.object(
                        store_module.ProductPaths,
                        "resolve",
                        side_effect=AssertionError(
                            "ProductPaths.resolve reached"
                        ),
                    ), mock.patch(
                        "os.path.realpath",
                        side_effect=AssertionError("realpath reached"),
                    ):
                with self.assertRaises(ValueError) as caught:
                    config_module.open_existing_private_data_root(
                        str(root)
                    )
            self.assertIn("symlink", str(caught.exception))
            self.assertTrue(state["swapped"])
            moved = True
        finally:
            if moved:
                os.unlink(str(auth))
                os.rename(str(base / "auth-old"), str(auth))

    def test_swap_after_seam_before_resolve_refuses_on_revalidation(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "swap-b"
        auth = base / "auth"
        root = auth / "root"
        (root / "profiles").mkdir(parents=True)
        os.chmod(base, 0o700)
        os.chmod(auth, 0o700)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        real_resolve = ProductPaths.resolve
        state = {"swapped": False}

        def resolve_then_swap(arg=None):
            if not state["swapped"]:
                state["swapped"] = True
                os.rename(str(auth), str(base / "auth-old"))
                os.symlink(str(base / "auth-old"), str(auth))
            return real_resolve(arg)

        moved = False
        try:
            with mock.patch.object(
                store_module.ProductPaths, "resolve", resolve_then_swap
            ):
                with self.assertRaises(ValueError) as caught:
                    ProfileStore.open_existing(str(root))
            # The identical-inode swap is caught by retained-chain name-entry
            # revalidation: 'auth' under the still-retained parent fd is now
            # a symlink, not the opened directory.
            self.assertIn("substituted after open", str(caught.exception))
            self.assertTrue(state["swapped"])
            moved = True
        finally:
            if moved:
                os.unlink(str(auth))
                os.rename(str(base / "auth-old"), str(auth))

    def test_regular_replacement_between_audit_and_openat_refuses(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "reg-swap"
        auth = base / "auth"
        root = auth / "root"
        (root / "profiles").mkdir(parents=True)
        for d in (base, auth, root, root / "profiles"):
            os.chmod(d, 0o700)
        old_digest = _tree_digest(auth)
        real_open = os.open
        state = {"swapped": False}
        new_digest: dict[str, str] = {}

        def replacing_open(path, flags, mode=0o777, dir_fd=None):
            if (
                not state["swapped"]
                and dir_fd is not None
                and path == "auth"
                and flags & os.O_NOFOLLOW
                and flags & os.O_DIRECTORY
            ):
                state["swapped"] = True
                os.rename(str(auth), str(base / "auth-old"))
                new_root = auth / "root"
                (new_root / "profiles").mkdir(parents=True)
                for d in (auth, new_root, new_root / "profiles"):
                    os.chmod(d, 0o700)
                (new_root / "profiles" / "marker.txt").write_text("new\n")
                new_digest["v"] = _tree_digest(auth)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        replaced = False
        try:
            with mock.patch.object(config_module.os, "open", replacing_open), \
                    mock.patch.object(
                        store_module.ProductPaths,
                        "resolve",
                        side_effect=AssertionError(
                            "ProductPaths.resolve reached"
                        ),
                    ), mock.patch(
                        "os.path.realpath",
                        side_effect=AssertionError("realpath reached"),
                    ):
                with self.assertRaises(ValueError) as caught:
                    config_module.open_existing_private_data_root(
                        str(root)
                    )
            self.assertIn(
                "was replaced after the lexical audit",
                str(caught.exception),
            )
            self.assertTrue(state["swapped"])
            # Exact accounting: the refusal never touched the replacement
            # tree; the original tree survives byte-identical under -old.
            self.assertEqual(new_digest["v"], _tree_digest(auth))
            replaced = True
        finally:
            if replaced:
                shutil.rmtree(str(auth))
                os.rename(str(base / "auth-old"), str(auth))
                self.assertEqual(old_digest, _tree_digest(auth))

    def test_final_chain_revalidation_refuses_data_home_mode_drift(self) -> None:
        import unittest.mock as mock

        root = pathlib.Path(self.root) / "drift-root"
        (root / "profiles").mkdir(parents=True)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        orig_revalidate = config_module.RetainedPrivateChain.revalidate
        state = {"chmodded": False}

        def drift_then_revalidate(self):
            if not state["chmodded"]:
                state["chmodded"] = True
                # Fires after canonical identity + profiles validation,
                # during the FINAL retained-chain revalidation.
                os.chmod(str(root), 0o755)
            return orig_revalidate(self)

        try:
            with mock.patch.object(
                config_module.RetainedPrivateChain,
                "revalidate",
                drift_then_revalidate,
            ):
                with self.assertRaises(ValueError) as caught:
                    ProfileStore.open_existing(str(root))
            self.assertIn("exactly 0700", str(caught.exception))
        finally:
            os.chmod(str(root), 0o700)
        self.assertTrue(state["chmodded"])
        self.assertEqual(0o700, os.stat(root).st_mode & 0o777)

    def test_injected_private_open_failure_leaks_no_fds(self) -> None:
        import unittest.mock as mock

        root = pathlib.Path(self.root) / "fd-pri"
        (root / "profiles").mkdir(parents=True)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        real_open = os.open

        def boom(path, flags, mode=0o777, dir_fd=None):
            if (
                path == "private"
                and dir_fd is not None
                and flags & os.O_NOFOLLOW
                and flags & os.O_DIRECTORY
            ):
                raise OSError(errno.EIO, "injected")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        baseline = sorted(os.listdir("/dev/fd"))
        with mock.patch.object(config_module.os, "open", boom):
            with self.assertRaises(ValueError) as caught:
                config_module.open_existing_private_data_root(str(root))
        self.assertIn(
            "trusted platform mount /private could not be opened safely",
            str(caught.exception),
        )
        self.assertEqual(baseline, sorted(os.listdir("/dev/fd")))

    def test_injected_hop_open_failure_leaks_no_fds(self) -> None:
        import unittest.mock as mock

        root = pathlib.Path(self.root) / "fd-hop"
        (root / "profiles").mkdir(parents=True)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        real_open = os.open

        def boom(path, flags, mode=0o777, dir_fd=None):
            if (
                path == "var"
                and dir_fd is not None
                and flags & os.O_NOFOLLOW
                and flags & os.O_DIRECTORY
            ):
                raise OSError(errno.EIO, "injected")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        baseline = sorted(os.listdir("/dev/fd"))
        with mock.patch.object(config_module.os, "open", boom):
            with self.assertRaises(ValueError) as caught:
                config_module.open_existing_private_data_root(str(root))
        self.assertIn(
            "trusted platform mount /private/var could not be opened safely",
            str(caught.exception),
        )
        self.assertEqual(baseline, sorted(os.listdir("/dev/fd")))

    def test_injected_private_bind_failure_leaks_no_fds(self) -> None:
        import unittest.mock as mock

        root = pathlib.Path(self.root) / "fd-bind-pri"
        (root / "profiles").mkdir(parents=True)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        real_stat = os.stat
        calls = {"n": 0}

        def boom_stat(path, **kwargs):
            if (
                path == "private"
                and calls["n"] == 0
                and kwargs.get("follow_symlinks") is False
                and kwargs.get("dir_fd") is not None
            ):
                calls["n"] += 1
                raise OSError(errno.EIO, "injected")
            return real_stat(path, **kwargs)

        baseline = sorted(os.listdir("/dev/fd"))
        with mock.patch.object(config_module.os, "stat", boom_stat):
            with self.assertRaises(ValueError) as caught:
                config_module.open_existing_private_data_root(str(root))
        self.assertIn("is not verifiable", str(caught.exception))
        self.assertEqual(1, calls["n"])
        self.assertEqual(baseline, sorted(os.listdir("/dev/fd")))

    def test_injected_hop_bind_failure_leaks_no_fds(self) -> None:
        import unittest.mock as mock

        root = pathlib.Path(self.root) / "fd-bind-hop"
        (root / "profiles").mkdir(parents=True)
        os.chmod(root, 0o700)
        os.chmod(root / "profiles", 0o700)
        real_stat = os.stat
        calls = {"n": 0}

        def boom_stat(path, **kwargs):
            if (
                path == "var"
                and calls["n"] == 0
                and kwargs.get("follow_symlinks") is False
                and kwargs.get("dir_fd") is not None
            ):
                calls["n"] += 1
                raise OSError(errno.EIO, "injected")
            return real_stat(path, **kwargs)

        baseline = sorted(os.listdir("/dev/fd"))
        with mock.patch.object(config_module.os, "stat", boom_stat):
            with self.assertRaises(ValueError) as caught:
                config_module.open_existing_private_data_root(str(root))
        self.assertIn("is not verifiable", str(caught.exception))
        self.assertEqual(1, calls["n"])
        self.assertEqual(baseline, sorted(os.listdir("/dev/fd")))

    def test_no_resnapshot_window_after_authoritative_audit(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "resnap"
        auth = base / "auth"
        root = auth / "root"
        (root / "profiles").mkdir(parents=True)
        for d in (base, auth, root, root / "profiles"):
            os.chmod(d, 0o700)
        old_digest = _tree_digest(auth)
        real_audit = config_module._audit_lexical_components_pure
        state = {"fired": False}
        new_digest: dict[str, str] = {}

        def audit_then_replace(path, *args, **kwargs):
            result = real_audit(path, *args, **kwargs)
            if not state["fired"] and pathlib.Path(path) == root:
                state["fired"] = True
                # The authoritative audit has captured the ORIGINAL tree;
                # replace it with a different ordinary 0700 tree BEFORE the
                # descriptor walk consumes the returned expectations.
                os.rename(str(auth), str(base / "auth-old"))
                new_root = auth / "root"
                (new_root / "profiles").mkdir(parents=True)
                for d in (auth, new_root, new_root / "profiles"):
                    os.chmod(d, 0o700)
                (new_root / "profiles" / "marker.txt").write_text("new\n")
                new_digest["v"] = _tree_digest(auth)
            return result

        replaced = False
        try:
            with mock.patch.object(
                config_module,
                "_audit_lexical_components_pure",
                audit_then_replace,
            ), mock.patch.object(
                store_module.ProductPaths,
                "resolve",
                side_effect=AssertionError("ProductPaths.resolve reached"),
            ), mock.patch(
                "os.path.realpath",
                side_effect=AssertionError("realpath reached"),
            ):
                with self.assertRaises(ValueError) as caught:
                    config_module.open_existing_private_data_root(str(root))
            # The walk must consume the OLD pre-audit identities and refuse
            # the replacement — a later resnapshot would accept it.
            self.assertIn(
                "was replaced after the lexical audit",
                str(caught.exception),
            )
            self.assertTrue(state["fired"])
            self.assertEqual(new_digest["v"], _tree_digest(auth))
            replaced = True
        finally:
            if replaced:
                shutil.rmtree(str(auth))
                os.rename(str(base / "auth-old"), str(auth))
                self.assertEqual(old_digest, _tree_digest(auth))

    def test_dotdot_alias_override_spelling_refuses_before_resolve(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "dot-ovr"
        sib = base / "sib"
        base.mkdir()
        sib.mkdir(mode=0o700)
        real = base / "real"
        (real / "root" / "profiles").mkdir(parents=True)
        for d in (base, real, real / "root", real / "root" / "profiles"):
            os.chmod(d, 0o700)
        alias = base / "alias"
        os.symlink(sib, alias)
        spelling = str(alias) + "/../root"
        before = _tree_digest(base)
        with mock.patch.object(
            store_module.ProductPaths,
            "resolve",
            side_effect=AssertionError("ProductPaths.resolve reached"),
        ), mock.patch(
            "os.path.realpath",
            side_effect=AssertionError("realpath reached"),
        ):
            with self.assertRaises(ValueError) as caught:
                ProfileStore.open_existing(spelling)
        self.assertIn("parent traversal", str(caught.exception))
        self.assertEqual(before, _tree_digest(base))

    def test_dotdot_alias_env_spelling_refuses_before_resolve(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "dot-env"
        sib = base / "sib"
        base.mkdir()
        sib.mkdir(mode=0o700)
        real = base / "real"
        (real / "root" / "profiles").mkdir(parents=True)
        for d in (base, real, real / "root", real / "root" / "profiles"):
            os.chmod(d, 0o700)
        alias = base / "alias"
        os.symlink(sib, alias)
        spelling = str(alias) + "/../root"
        before = _tree_digest(base)
        with mock.patch.dict(
            os.environ, {config_module.DATA_HOME_ENV: spelling}
        ), mock.patch.object(
            store_module.ProductPaths,
            "resolve",
            side_effect=AssertionError("ProductPaths.resolve reached"),
        ), mock.patch(
            "os.path.realpath",
            side_effect=AssertionError("realpath reached"),
        ):
            with self.assertRaises(ValueError) as caught:
                config_module.open_existing_private_data_root()
        self.assertIn("parent traversal", str(caught.exception))
        self.assertEqual(before, _tree_digest(base))

    def test_normalized_valid_positive_constructs_store_without_write(self) -> None:
        real = pathlib.Path(self.root) / "pos"
        (real / "root" / "profiles").mkdir(parents=True)
        for d in (real, real / "root", real / "root" / "profiles"):
            os.chmod(d, 0o700)
        before = _tree_digest(real)
        fitted = ProfileStore.open_existing(str(real / "root"))
        self.assertEqual((real / "root").resolve(), fitted.paths.root)
        self.assertEqual(before, _tree_digest(real))

    def test_non_normal_spellings_refuse_objectively(self) -> None:
        import unittest.mock as mock

        base = pathlib.Path(self.root) / "nonnormal"
        base.mkdir(mode=0o700)
        before = _tree_digest(base)
        cases = [
            (str(base) + "/../side", "parent traversal"),
            (str(base) + "/./side", "self component"),
            (str(base) + "//side", "empty component"),
            (str(base) + "/side/", "empty component"),
            ("", "spelling is empty"),
        ]
        for spelling, expected_fragment in cases:
            with mock.patch.object(
                store_module.ProductPaths,
                "resolve",
                side_effect=AssertionError("ProductPaths.resolve reached"),
            ), mock.patch(
                "os.path.realpath",
                side_effect=AssertionError("realpath reached"),
            ):
                with self.subTest(delivery="override", spelling=spelling):
                    with self.assertRaises(ValueError) as caught:
                        ProfileStore.open_existing(spelling)
                    self.assertIn(expected_fragment, str(caught.exception))
                with self.subTest(delivery="env", spelling=spelling):
                    with mock.patch.dict(
                        os.environ,
                        {config_module.DATA_HOME_ENV: spelling},
                    ):
                        with self.assertRaises(ValueError) as caught_env:
                            config_module.open_existing_private_data_root()
                    self.assertIn(expected_fragment, str(caught_env.exception))
        self.assertFalse((base / "side").exists())
        self.assertEqual(before, _tree_digest(base))

    def test_env_empty_refuses_before_default_or_resolve(self) -> None:
        import unittest.mock as mock

        captured: dict[str, str] = {}
        real_gate = config_module._normal_absolute_private_spelling

        def gate_spy(textual):
            captured["raw"] = textual
            return real_gate(textual)

        before = _tree_digest(pathlib.Path(self.root))
        home_default = (
            pathlib.Path(os.path.expanduser("~"))
            / ".local"
            / "share"
            / "market-aligner"
        )
        had_default = home_default.exists()
        default_stat = os.lstat(home_default) if had_default else None
        with mock.patch.dict(
            os.environ, {config_module.DATA_HOME_ENV: ""}
        ), mock.patch.object(
            store_module.ProductPaths,
            "resolve",
            side_effect=AssertionError("ProductPaths.resolve reached"),
        ), mock.patch(
            "os.path.realpath",
            side_effect=AssertionError("realpath reached"),
        ), mock.patch.object(
            config_module,
            "_normal_absolute_private_spelling",
            gate_spy,
        ):
            with self.assertRaises(ValueError) as caught:
                config_module.open_existing_private_data_root()
        self.assertIn("spelling is empty", str(caught.exception))
        # The EMPTY value itself reached the gate: the canonical default was
        # never selected or spelled.
        self.assertEqual("", captured["raw"])
        self.assertEqual(before, _tree_digest(pathlib.Path(self.root)))
        if had_default and default_stat is not None:
            self.assertEqual(
                (
                    default_stat.st_mode,
                    default_stat.st_ino,
                    default_stat.st_size,
                    default_stat.st_mtime_ns,
                ),
                (
                    os.lstat(home_default).st_mode,
                    os.lstat(home_default).st_ino,
                    os.lstat(home_default).st_size,
                    os.lstat(home_default).st_mtime_ns,
                ),
            )

    def test_env_absent_selects_canonical_default_without_creation(self) -> None:
        import unittest.mock as mock

        captured: dict[str, str] = {}
        real_gate = config_module._normal_absolute_private_spelling

        def gate_spy(textual):
            captured["raw"] = textual
            return real_gate(textual)

        env_copy = {
            k: v for k, v in os.environ.items()
            if k != config_module.DATA_HOME_ENV
        }
        home_default = (
            pathlib.Path(os.path.expanduser("~"))
            / ".local"
            / "share"
            / "market-aligner"
        )
        existed_before = home_default.exists()
        before = _tree_digest(pathlib.Path(self.root))
        with mock.patch.dict(os.environ, env_copy, clear=True), mock.patch.object(
            store_module.ProductPaths,
            "resolve",
            side_effect=AssertionError("ProductPaths.resolve reached"),
        ), mock.patch(
            "os.path.realpath",
            side_effect=AssertionError("realpath reached"),
        ), mock.patch.object(
            config_module,
            "_normal_absolute_private_spelling",
            gate_spy,
        ):
            try:
                chain = config_module.open_existing_private_data_root()
            except ValueError:
                chain = None
        expected_default = os.path.join(
            os.path.expanduser("~"),
            ".local",
            "share",
            "market-aligner",
        )
        self.assertEqual(expected_default, captured["raw"])
        if chain is not None:
            chain.close()
        if not existed_before:
            self.assertFalse(home_default.exists())
        self.assertEqual(before, _tree_digest(pathlib.Path(self.root)))

    def test_tests_never_bypass_constructors_with_new(self) -> None:
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertNotIn("__" + "new__", source)


# ---------------------------------------------------------------------------
# Legacy vs sealed lifecycle (§6 legacy compatibility; §21 coherence gates)
# ---------------------------------------------------------------------------


class LegacyAndSealLifecycleTests(TempRootTestCase):
    def test_manifest_absent_snapshot_is_explicit_legacy_unsealed_no_write(
        self,
    ) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [_evidence()])
        _drop_manifest(store)
        digest = _tree_digest(pathlib.Path(self.root))
        snapshot = store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertTrue(snapshot.legacy_unsealed)
            self.assertIsNone(snapshot.manifest)
            self.assertEqual("v1", snapshot.profile.version)
            snapshot.revalidate()
        finally:
            snapshot.close()
        self.assertEqual(digest, _tree_digest(pathlib.Path(self.root)))

    def test_fit_seam_requires_committed_and_refuses_legacy_pair(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [])
        _drop_manifest(store)
        with self.assertRaises(ValueError) as caught:
            store.coherent_snapshot(PID)
        self.assertIn("committed generation manifest", str(caught.exception))

    def test_in_progress_generation_refuses_fit(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [_evidence()])
        profile_sha = hashlib.sha256(
            (store.directory(PID) / PROFILE_NAME).read_bytes()
        ).hexdigest()
        evidence_sha = hashlib.sha256(
            (store.directory(PID) / EVIDENCE_NAME).read_bytes()
        ).hexdigest()
        _write_leaf(
            store,
            MANIFEST_NAME,
            _expected_manifest("in_progress", profile_sha, evidence_sha),
        )
        with self.assertRaises(ValueError) as caught:
            store.coherent_snapshot(PID)
        self.assertIn("refuses FIT", str(caught.exception))

    def test_first_successful_save_seals_exact_committed_generation(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(version="v1"), [_evidence()])
        manifest = _parse_manifest(_manifest_bytes(store.directory(PID)))
        self.assertEqual("committed", manifest["state"])
        snapshot = store.coherent_snapshot(PID)
        try:
            self.assertFalse(snapshot.legacy_unsealed)
            self.assertEqual("v1", snapshot.profile.version)
            self.assertEqual(
                manifest["profile_file_sha256"],
                snapshot.hashes["profile_file_sha256"],
            )
            self.assertEqual(
                manifest["evidence_file_sha256"],
                snapshot.hashes["evidence_file_sha256"],
            )
        finally:
            snapshot.close()

    def test_second_save_updates_exact_committed_manifest_and_leaves(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(version="v1"), [_evidence()])
        first = _manifest_bytes(store.directory(PID))
        first_inode = os.stat(store.directory(PID) / MANIFEST_NAME).st_ino
        store.save(_profile(version="v2"), [_evidence(), _evidence("ev2")])
        second = _manifest_bytes(store.directory(PID))
        second_inode = os.stat(store.directory(PID) / MANIFEST_NAME).st_ino
        self.assertNotEqual(first, second)
        self.assertNotEqual(first_inode, second_inode)  # republished, not edited
        manifest = _parse_manifest(second)
        self.assertEqual("committed", manifest["state"])
        self.assertEqual(
            hashlib.sha256(
                (store.directory(PID) / PROFILE_NAME).read_bytes()
            ).hexdigest(),
            manifest["profile_file_sha256"],
        )
        loaded, ledger = store.load(PID)
        self.assertEqual("v2", loaded.version)
        self.assertEqual(2, len(ledger))


# ---------------------------------------------------------------------------
# Manifest canonical shape positives (§6 six-key/self-hash/bounds)
# ---------------------------------------------------------------------------


class ManifestCanonicalShapeTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [_evidence()])
        self.directory = self.store.directory(PID)

    def test_exact_six_canonical_keys_single_lf_within_bound(self) -> None:
        raw = _manifest_bytes(self.directory)
        self.assertLessEqual(len(raw), MAX_MANIFEST_BYTES)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        text = raw.decode("utf-8")
        self.assertEqual(
            text,
            json.dumps(
                json.loads(text),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )
        self.assertEqual(
            {
                "schema_version",
                "state",
                "profile_id",
                "profile_file_sha256",
                "evidence_file_sha256",
                "generation_sha256",
            },
            set(json.loads(text)),
        )

    def test_self_hash_binds_exactly_the_five_key_object(self) -> None:
        manifest = _parse_manifest(_manifest_bytes(self.directory))
        five = {
            key: value
            for key, value in manifest.items()
            if key != "generation_sha256"
        }
        canonical = json.dumps(
            five, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        self.assertEqual(
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            manifest["generation_sha256"],
        )

    def test_manifest_leaf_metadata_is_private_single_link(self) -> None:
        info = os.lstat(self.directory / MANIFEST_NAME)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(os.getuid(), info.st_uid)
        self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        self.assertEqual(1, info.st_nlink)

    def test_state_and_hash_fields_match_published_leaves(self) -> None:
        manifest = _parse_manifest(_manifest_bytes(self.directory))
        self.assertEqual("committed", manifest["state"])
        self.assertEqual(PID, manifest["profile_id"])
        self.assertEqual(MANIFEST_SCHEMA, manifest["schema_version"])
        self.assertEqual(
            hashlib.sha256((self.directory / PROFILE_NAME).read_bytes()).hexdigest(),
            manifest["profile_file_sha256"],
        )
        self.assertEqual(
            hashlib.sha256((self.directory / EVIDENCE_NAME).read_bytes()).hexdigest(),
            manifest["evidence_file_sha256"],
        )


# ---------------------------------------------------------------------------
# Manifest negative matrix: refuse without write (§6 classification rules)
# ---------------------------------------------------------------------------


class ManifestNegativeMatrixTests(TempRootTestCase):
    """Every mutation recaptures its own no-write baseline."""

    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [_evidence()])
        self.directory = self.store.directory(PID)

    def _assert_refusal_no_write(self, digest: list) -> None:
        with self.assertRaises((ValueError, OSError)):
            self.store.snapshot(PID, require_committed_generation=False)
        with self.assertRaises((ValueError, OSError)):
            self.store.coherent_snapshot(PID)
        self.assertEqual(digest, _tree_digest(pathlib.Path(self.root)))

    def _mutated(self, payload: bytes, mode: int = 0o600) -> list:
        _write_leaf(self.store, MANIFEST_NAME, payload)
        if mode != 0o600:
            os.chmod(self.directory / MANIFEST_NAME, mode)
        return _tree_digest(pathlib.Path(self.root))

    def _current_manifest(self) -> dict:
        return _parse_manifest(_manifest_bytes(self.directory))

    def test_malformed_manifest_bytes_refuse(self) -> None:
        digest = self._mutated(b"{not json at all")
        self._assert_refusal_no_write(digest)

    def test_noncanonical_pretty_json_refuse(self) -> None:
        pretty = json.dumps(self._current_manifest(), indent=2, sort_keys=True)
        digest = self._mutated((pretty + "\n").encode("utf-8"))
        self._assert_refusal_no_write(digest)

    def test_duplicate_key_manifest_refuse(self) -> None:
        raw = _manifest_bytes(self.directory)
        poisoned = raw.replace(
            b"{", b'{"evidence_file_sha256":"x",', 1
        )
        self.assertNotEqual(raw, poisoned)
        digest = self._mutated(poisoned)
        self._assert_refusal_no_write(digest)

    def test_extra_final_newline_manifest_refuse(self) -> None:
        digest = self._mutated(_manifest_bytes(self.directory) + b"\n")
        self._assert_refusal_no_write(digest)

    def test_unknown_extra_key_refuse(self) -> None:
        manifest = self._current_manifest()
        manifest["extra"] = "field"
        digest = self._mutated(_canonical(manifest))
        self._assert_refusal_no_write(digest)

    def test_missing_key_refuse(self) -> None:
        manifest = self._current_manifest()
        del manifest["evidence_file_sha256"]
        digest = self._mutated(_canonical(manifest))
        self._assert_refusal_no_write(digest)

    def test_wrong_schema_version_refuse(self) -> None:
        manifest = self._current_manifest()
        manifest["schema_version"] = "market-aligner.profile-generation.v2"
        digest = self._mutated(_canonical(manifest))
        self._assert_refusal_no_write(digest)

    def test_invalid_state_value_refuse(self) -> None:
        manifest = self._current_manifest()
        manifest["state"] = "sealed"
        digest = self._mutated(_canonical(manifest))
        self._assert_refusal_no_write(digest)

    def test_wrong_profile_binding_refuse(self) -> None:
        profile_sha = hashlib.sha256(
            (self.directory / PROFILE_NAME).read_bytes()).hexdigest()
        evidence_sha = hashlib.sha256(
            (self.directory / EVIDENCE_NAME).read_bytes()).hexdigest()
        digest = self._mutated(
            _expected_manifest("committed", profile_sha, evidence_sha,
                               profile_id=OTHER_PID)
        )
        self._assert_refusal_no_write(digest)

    def test_corrupt_self_hash_refuse(self) -> None:
        manifest = self._current_manifest()
        head = manifest["generation_sha256"][0]
        flipped = "0" if head != "0" else "1"
        manifest["generation_sha256"] = flipped + manifest[
            "generation_sha256"
        ][1:]
        digest = self._mutated(_canonical(manifest))
        self._assert_refusal_no_write(digest)

    def test_symlinked_manifest_refuse(self) -> None:
        os.unlink(self.directory / MANIFEST_NAME)
        os.symlink(".decoy-generation.json", self.directory / MANIFEST_NAME)
        digest = _tree_digest(pathlib.Path(self.root))
        try:
            self._assert_refusal_no_write(digest)
        finally:
            os.unlink(self.directory / MANIFEST_NAME)

    def test_hardlinked_manifest_refuse(self) -> None:
        os.link(self.directory / MANIFEST_NAME, self.directory / ".alias-gen")
        digest = _tree_digest(pathlib.Path(self.root))
        try:
            self._assert_refusal_no_write(digest)
        finally:
            os.unlink(self.directory / ".alias-gen")

    def test_wrong_mode_manifest_refuse_without_chmod(self) -> None:
        os.chmod(self.directory / MANIFEST_NAME, 0o644)
        digest = _tree_digest(pathlib.Path(self.root))
        before = stat.S_IMODE(os.lstat(self.directory / MANIFEST_NAME).st_mode)
        self._assert_refusal_no_write(digest)
        self.assertEqual(
            before, stat.S_IMODE(os.lstat(self.directory / MANIFEST_NAME).st_mode)
        )

    def test_oversize_manifest_refuse_at_boundary(self) -> None:
        digest = self._mutated(b"x" * (MAX_MANIFEST_BYTES + 1))
        self._assert_refusal_no_write(digest)

    def test_committed_manifest_leaf_hash_mismatch_refuse(self) -> None:
        digest = self._mutated(_expected_manifest("committed", "f" * 64, "e" * 64))
        self._assert_refusal_no_write(digest)


class SaveSupersedeRefusalTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [_evidence()])
        self.directory = self.store.directory(PID)

    def _assert_save_refuses_no_write(self, digest: list) -> None:
        with self.assertRaises((ValueError, OSError)):
            self.store.save(_profile(version="mutant"), [])
        self.assertEqual(digest, _tree_digest(pathlib.Path(self.root)))

    def test_save_refuses_malformed_prior_manifest(self) -> None:
        _write_leaf(self.store, MANIFEST_NAME, b"garbage{")
        self._assert_save_refuses_no_write(
            _tree_digest(pathlib.Path(self.root))
        )

    def test_save_refuses_wrong_mode_prior_manifest(self) -> None:
        os.chmod(self.directory / MANIFEST_NAME, 0o666)
        self._assert_save_refuses_no_write(
            _tree_digest(pathlib.Path(self.root))
        )

    def test_save_refuses_mismatched_committed_prior(self) -> None:
        _write_leaf(
            self.store,
            MANIFEST_NAME,
            _expected_manifest("committed", "a" * 64, "b" * 64),
        )
        self._assert_save_refuses_no_write(
            _tree_digest(pathlib.Path(self.root))
        )

    def test_pre_mutation_fault_propagates_original_after_proof(self) -> None:
        # Contract-honest NON-EXACT canonical-entry comparison (both sides):
        # the handled fault fires after mutation began — the manifest temp is
        # legitimately created and unlinked — which churns the profile
        # directory mtime without leaving any entry behind. Every entry and
        # every file/other mtime must match exactly; only directory mtimes
        # are exempted on BOTH captures.
        baseline = _tree_digest(
            pathlib.Path(self.root), include_dir_mtime=False
        )
        cause = OSError("boom-pre-mutation")
        with store_module._fault_at(STEP1_TEMPSYNC, cause):
            with self.assertRaises(OSError) as caught:
                self.store.save(_profile(version="pre"), [])
        self.assertIs(cause, caught.exception)
        self.assertEqual(
            baseline,
            _tree_digest(pathlib.Path(self.root), include_dir_mtime=False),
        )


# ---------------------------------------------------------------------------
# Handled-fault campaign across every accepted publication boundary (§21)
# ---------------------------------------------------------------------------


class PublicationOrderFaultTests(TempRootTestCase):
    """One injected handled failure per accepted boundary, then recovery."""

    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(version="base"), [_evidence()])
        self.base_profile_sha = hashlib.sha256(
            (self.store.directory(PID) / PROFILE_NAME).read_bytes()
        ).hexdigest()

    def _faulted_save(self, boundary: str) -> BaseException:
        cause = OSError(f"injected:{boundary}")
        with store_module._fault_at(boundary, cause):
            with self.assertRaises(BaseException) as caught:
                self.store.save(_profile(version="next"), [_evidence()])
        return caught.exception

    def _classification_coherent(self) -> None:
        """Fresh locked classification admits nothing mixed or false."""
        try:
            snapshot = self.store.coherent_snapshot(PID)
        except (ValueError, OSError):
            return
        try:
            self.assertEqual("committed", snapshot.manifest["state"])
            self.assertEqual(
                snapshot.manifest["profile_file_sha256"],
                snapshot.hashes["profile_file_sha256"],
            )
        finally:
            snapshot.close()

    def _retry_recovers(self) -> None:
        self.store.save(_profile(version="recovered"), [])
        snapshot = self.store.coherent_snapshot(PID)
        try:
            self.assertEqual("recovered", snapshot.profile.version)
        finally:
            snapshot.close()

    def test_step1_temp_fsync_failure_keeps_prior_committed_intact(self) -> None:
        outcome = self._faulted_save(STEP1_TEMPSYNC)
        self.assertIsInstance(outcome, OSError)
        self.assertIn("injected:", str(outcome))
        self.assertEqual(
            self.base_profile_sha,
            hashlib.sha256(
                (self.store.directory(PID) / PROFILE_NAME).read_bytes()
            ).hexdigest(),
        )
        self._classification_coherent()
        self._retry_recovers()

    def _assert_unknown_outcome(self, boundary: str) -> None:
        outcome = self._faulted_save(boundary)
        self.assertIsInstance(outcome, ProfileGenerationOutcomeUnknown)
        self.assertNotIsInstance(outcome, DurableInProgressSaveFailed)
        self._classification_coherent()
        self._retry_recovers()

    def test_initial_rename_unbarriered_is_unknown(self) -> None:
        self._assert_unknown_outcome(BOUNDARY_INITIAL_RENAME)

    def test_initial_dirfsync_still_unbarriered_is_unknown(self) -> None:
        self._assert_unknown_outcome(BOUNDARY_INITIAL_DIRFSYNC)

    def _assert_durable_in_progress(self, boundary: str) -> None:
        outcome = self._faulted_save(boundary)
        self.assertIsInstance(outcome, DurableInProgressSaveFailed)
        raw = _manifest_bytes(self.store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        self._classification_coherent()
        self._retry_recovers()

    def test_step1_barrier_completion_enables_durable_claim(self) -> None:
        self._assert_durable_in_progress(BOUNDARY_STEP1_BARRIER)

    def test_leaf_temp_fsync_failure_is_durable_in_progress(self) -> None:
        self._assert_durable_in_progress(BOUNDARY_LEAF_TEMPSYNC)

    def test_leaf_renames_failure_is_durable_in_progress(self) -> None:
        self._assert_durable_in_progress(BOUNDARY_LEAF_RENAMES)

    def test_content_barrier_failure_is_durable_in_progress(self) -> None:
        self._assert_durable_in_progress(BOUNDARY_CONTENT_BARRIER)

    def test_content_verify_failure_is_durable_in_progress(self) -> None:
        self._assert_durable_in_progress(BOUNDARY_CONTENT_VERIFY)

    def test_committed_temp_fsync_failure_is_durable_in_progress(self) -> None:
        self._assert_durable_in_progress(BOUNDARY_COMMITTED_TEMPSYNC)

    def test_committed_rename_triggers_proven_rollback_republish(self) -> None:
        outcome = self._faulted_save(BOUNDARY_COMMITTED_RENAME)
        self.assertIsInstance(outcome, DurableInProgressSaveFailed)
        raw = _manifest_bytes(self.store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        self._classification_coherent()
        self._retry_recovers()

    def test_final_dirfsync_failure_never_reports_success(self) -> None:
        outcome = self._faulted_save(BOUNDARY_FINAL_DIRFSYNC)
        self.assertIsInstance(outcome, DurableInProgressSaveFailed)
        raw = _manifest_bytes(self.store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        with self.assertRaises((ValueError, OSError)):
            self.store.coherent_snapshot(PID)
        self._retry_recovers()

    def test_first_save_pre_mutation_fault_keeps_tree_absent(self) -> None:
        fresh_root = tempfile.TemporaryDirectory()
        try:
            fresh_store = _new_store(fresh_root.name)
            cause = OSError("first-save-boom")
            with store_module._fault_at(STEP1_TEMPSYNC, cause):
                with self.assertRaises(OSError) as caught:
                    fresh_store.save(_profile(), [_evidence()])
            self.assertIs(cause, caught.exception)
            entries = (
                os.listdir(fresh_store.paths.profiles)
                if fresh_store.paths.profiles.is_dir()
                else []
            )
            self.assertIn(entries, ([], [PID]))
            if PID in entries:
                self.assertEqual([], os.listdir(fresh_store.paths.profiles / PID))
        finally:
            fresh_root.cleanup()


# ---------------------------------------------------------------------------
# Rollback hooks paired with after_committed_rename (§21 rollback gates)
# ---------------------------------------------------------------------------


class RollbackHookTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(version="base"), [])
        self.directory = self.store.directory(PID)

    def _pair_with_broken_hook(self, hook: str) -> BaseException:
        crash = OSError("crash-after-committed-rename")
        hook_exc = OSError(f"rollback-broken:{hook}")
        with store_module._fault_at(BOUNDARY_COMMITTED_RENAME, crash), \
                store_module._fault_at(hook, hook_exc):
            with self.assertRaises(BaseException) as caught:
                self.store.save(_profile(version="next"), [])
        return caught.exception

    def _leftover_temps(self) -> list:
        return [
            name
            for name in os.listdir(self.directory)
            if name.startswith(".tmp-")
        ]

    def test_clean_rollback_yields_proven_durable_in_progress(self) -> None:
        crash = OSError("crash-after-committed-rename")
        with store_module._fault_at(BOUNDARY_COMMITTED_RENAME, crash):
            with self.assertRaises(DurableInProgressSaveFailed):
                self.store.save(_profile(version="next"), [])
        raw = _manifest_bytes(self.directory)
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        self.assertEqual([], self._leftover_temps())  # truthful temp outcome
        self.store.save(_profile(version="healed"), [])
        snapshot = self.store.coherent_snapshot(PID)
        try:
            self.assertEqual("healed", snapshot.profile.version)
        finally:
            snapshot.close()

    def test_every_broken_hook_forces_unknown_not_durable(self) -> None:
        for hook in ROLLBACK_HOOKS:
            with self.subTest(hook=hook):
                outcome = self._pair_with_broken_hook(hook)
                self.assertIsInstance(outcome, ProfileGenerationOutcomeUnknown)
                self.assertNotIsInstance(outcome, DurableInProgressSaveFailed)
                for leftover in self._leftover_temps():
                    os.unlink(self.directory / leftover)

    def test_recovery_after_broken_hook_stays_coherent(self) -> None:
        outcome = self._pair_with_broken_hook("rollback_rename")
        self.assertIsInstance(outcome, ProfileGenerationOutcomeUnknown)
        # Fresh-lock classification is the sole recovery authority.
        self._admit_only_coherent_committed()
        for leftover in self._leftover_temps():
            os.unlink(self.directory / leftover)
        self.store.save(_profile(version="post-unknown"), [])
        snapshot = self.store.coherent_snapshot(PID)
        try:
            self.assertEqual("post-unknown", snapshot.profile.version)
        finally:
            snapshot.close()

    def _admit_only_coherent_committed(self) -> None:
        try:
            snapshot = self.store.coherent_snapshot(PID)
        except (ValueError, OSError):
            return
        try:
            self.assertEqual("committed", snapshot.manifest["state"])
        finally:
            snapshot.close()

    def test_unknown_cause_survives_failed_rollback_verbatim(self) -> None:
        synthetic = ProfileGenerationOutcomeUnknown("synthetic-unknown")
        broken = OSError("rollback-dirfsync-broken")
        with store_module._fault_at(BOUNDARY_COMMITTED_RENAME, synthetic), \
                store_module._fault_at("rollback_dirfsync", broken):
            with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                self.store.save(_profile(version="next"), [])
        self.assertIs(synthetic, caught.exception)
        for leftover in self._leftover_temps():
            os.unlink(self.directory / leftover)


# ---------------------------------------------------------------------------
# Durable-phase unknown is never downgraded (save handler ordering)
# ---------------------------------------------------------------------------


class DurablePhaseNonDowngradeTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(version="base"), [])

    def test_synthetic_unknown_at_step1_barrier_propagates_directly(self) -> None:
        synthetic = ProfileGenerationOutcomeUnknown("synthetic-step1")
        with store_module._fault_at(BOUNDARY_STEP1_BARRIER, synthetic):
            with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                self.store.save(_profile(version="next"), [])
        self.assertIs(synthetic, caught.exception)
        self.assertNotIsInstance(caught.exception, DurableInProgressSaveFailed)

    def test_synthetic_unknown_at_committed_temp_fsync_propagates(self) -> None:
        synthetic = ProfileGenerationOutcomeUnknown("synthetic-committed-temp")
        with store_module._fault_at(BOUNDARY_COMMITTED_TEMPSYNC, synthetic):
            with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                self.store.save(_profile(version="next"), [])
        self.assertIs(synthetic, caught.exception)
        self.assertNotIsInstance(caught.exception, DurableInProgressSaveFailed)


# ---------------------------------------------------------------------------
# Direct _make_temp ownership/cleanup contract (sticky close failure)
# ---------------------------------------------------------------------------


class MakeTempDirectTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.hold_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.hold_dir.cleanup)
        self.dir_fd = os.open(self.hold_dir.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(lambda: os.close(self.dir_fd))
        self.owner = _new_store(self.root)
        self.make_temp = self.owner._make_temp
        self.payload = b"x" * 64

    def _leftovers(self) -> list:
        return [
            name
            for name in os.listdir(self.hold_dir.name)
            if name.startswith(".tmp-")
        ]

    def test_success_returns_name_and_identity_with_no_leftover(self) -> None:
        name, identity = self.make_temp(self.dir_fd, "ok", self.payload)
        try:
            info = os.stat(name, dir_fd=self.dir_fd, follow_symlinks=False)
            self.assertEqual(identity[1], info.st_ino)
            self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        finally:
            os.unlink(name, dir_fd=self.dir_fd)
        self.assertEqual([], self._leftovers())

    def test_write_failure_propagates_original_and_cleans(self) -> None:
        import unittest.mock as mock

        real_fsync = os.fsync
        fsynced: list[int] = []

        def spy_fsync(fd):
            fsynced.append(fd)
            return real_fsync(fd)

        def boom(fd, data):
            raise OSError("write boom")

        with mock.patch.object(store_module.os, "write", boom), \
                mock.patch.object(store_module.os, "fsync", spy_fsync):
            with self.assertRaises(OSError) as caught:
                self.make_temp(self.dir_fd, "t", self.payload)
        self.assertNotIsInstance(
            caught.exception, ProfileGenerationOutcomeUnknown
        )
        self.assertEqual("write boom", str(caught.exception))
        # The only fsync reachable after the write failure is the cleanup
        # directory fsync; it must have run exactly on the held dir_fd.
        self.assertEqual([self.dir_fd], fsynced)
        self.assertEqual([], self._leftovers())

    def test_fsync_failure_propagates_original_and_cleans(self) -> None:
        import unittest.mock as mock

        real_fsync = os.fsync
        calls = [0]

        def boom_once(fd):
            calls[0] += 1
            if calls[0] == 1:
                raise OSError("fsync boom")
            return real_fsync(fd)

        with mock.patch.object(store_module.os, "fsync", boom_once):
            with self.assertRaises(OSError) as caught:
                self.make_temp(self.dir_fd, "t", self.payload)
        self.assertEqual("fsync boom", str(caught.exception))
        self.assertEqual([], self._leftovers())

    def test_first_close_failure_is_sticky_unknown_even_when_retry_works(
        self,
    ) -> None:
        import unittest.mock as mock

        real_close = os.close
        calls = [0]

        def boom_then_real(fd):
            calls[0] += 1
            if calls[0] == 1:
                raise OSError("close boom once")
            return real_close(fd)

        with mock.patch.object(store_module.os, "close", boom_then_real):
            with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                self.make_temp(self.dir_fd, "t", self.payload)
        self.assertIn("close boom once", repr(caught.exception.__cause__))
        self.assertEqual([], self._leftovers())

    def test_always_failing_close_is_unknown_and_name_absent(self) -> None:
        import unittest.mock as mock

        real_close = os.close
        captured: list[int] = []

        def dead_close(fd):
            captured.append(fd)
            raise OSError("close dead")

        baseline = sorted(os.listdir("/dev/fd"))
        try:
            with mock.patch.object(store_module.os, "close", dead_close):
                with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                    self.make_temp(self.dir_fd, "t", self.payload)
            self.assertIn("close dead", repr(caught.exception.__cause__))
            unique_fds = list(dict.fromkeys(captured))
            self.assertGreaterEqual(len(unique_fds), 1)
            info = os.fstat(unique_fds[0])  # live: no EBADF
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(0, info.st_nlink)  # unlinked-descriptor truth
            self.assertEqual([], self._leftovers())
        finally:
            # Patch has exited; close every unique live fd with the real
            # os.close even if an assertion above failed. Only EBADF for an
            # already-closed duplicate is tolerated; any other close error
            # re-raises.
            for fd in dict.fromkeys(captured):
                try:
                    real_close(fd)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        self.assertEqual(baseline, sorted(os.listdir("/dev/fd")))

    def test_unlink_failure_yields_unknown_and_truthfully_persists(self) -> None:
        import unittest.mock as mock

        real_unlink = os.unlink

        def sabotage(target, **kwargs):
            if kwargs.get("dir_fd") is not None and str(target).startswith(
                ".tmp-"
            ):
                raise OSError("unlink sabotaged")
            return real_unlink(target, **kwargs)

        def boom(fd, data):
            raise OSError("write boom")

        with mock.patch.object(store_module.os, "write", boom), \
                mock.patch.object(store_module.os, "unlink", sabotage):
            with self.assertRaises(ProfileGenerationOutcomeUnknown):
                self.make_temp(self.dir_fd, "t", self.payload)
        self.assertEqual(1, len(self._leftovers()))
        for leftover in self._leftovers():
            os.unlink(leftover, dir_fd=self.dir_fd)

    def test_open_absence_failure_propagates_original(self) -> None:
        import unittest.mock as mock

        def enoent(*args, **kwargs):
            raise OSError(errno.ENOENT, "no such file")

        with mock.patch.object(store_module.os, "open", enoent):
            with self.assertRaises(OSError) as caught:
                self.make_temp(self.dir_fd, "t", self.payload)
        self.assertNotIsInstance(
            caught.exception, ProfileGenerationOutcomeUnknown
        )
        self.assertEqual(errno.ENOENT, caught.exception.errno)

    def test_open_collision_with_present_name_is_unknown(self) -> None:
        import unittest.mock as mock

        real_open = os.open
        state = {"first": True}

        def create_then_eexist(path, flags, mode=None, dir_fd=None):
            if state["first"] and dir_fd is not None:
                state["first"] = False
                fd = real_open(path, flags, mode or 0o600, dir_fd=dir_fd)
                os.close(fd)  # leave the generated name genuinely present
                raise OSError(errno.EEXIST, "collision", path)
            return real_open(path, flags, mode or 0o600, dir_fd=dir_fd)

        with mock.patch.object(store_module.os, "open", create_then_eexist):
            with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                self.make_temp(self.dir_fd, "t", self.payload)
        self.assertIn("collision", repr(caught.exception.__cause__))
        for leftover in self._leftovers():
            os.unlink(leftover, dir_fd=self.dir_fd)

    def test_cleanup_directory_fsync_called_and_its_failure_is_unknown(
        self,
    ) -> None:
        import unittest.mock as mock

        fsync_calls: list[int] = []

        def boom(fd, data):
            raise OSError("write boom")

        def fsync_sabotage(fd):
            fsync_calls.append(fd)
            raise OSError("cleanup fsync dead")

        with mock.patch.object(store_module.os, "write", boom), \
                mock.patch.object(store_module.os, "fsync", fsync_sabotage):
            with self.assertRaises(ProfileGenerationOutcomeUnknown) as caught:
                self.make_temp(self.dir_fd, "t", self.payload)
        # The only fsync reachable after the write failure is the cleanup
        # directory fsync; its recorded fd proves it ran against dir_fd.
        self.assertEqual([self.dir_fd], fsync_calls)
        self.assertIn("write boom", repr(caught.exception.__cause__))
        self.assertEqual([], self._leftovers())  # unlink proved, fsync did not


# ---------------------------------------------------------------------------
# Subprocess SIGKILL recovery campaign (§21 process death at boundaries)
# ---------------------------------------------------------------------------

# fsync sequence inside one killed save: 1 manifest-temp, 2 step-1 barrier,
# 3 profile-temp, 4 evidence-temp, 5 content barrier, 6 committed-temp,
# 7 final barrier. Rename sequence: 1 initial manifest, 2 profile,
# 3 evidence, 4 committed.


def _build_kill_child(src: str, root: str, target: str, index: int,
                      baseline: bool) -> str:
    return f'''
import os, signal, sys
sys.path.insert(0, {src!r})
from market_aligner.profiler.schema import CandidateProfile, TrackProfile
import market_aligner.profiler.store as S

PID = {PID!r}

def profile(version):
    return CandidateProfile(
        profile_id=PID,
        version=version,
        tracks={{"automation": TrackProfile(
            interest=1.0, demonstrated_skill=1.0, confidence=1.0,
            market_readiness=1.0, rationale="child")}},
    )

store = S.ProfileStore({root!r})
if {baseline!r}:
    store.save(profile("base"), [])

real_fsync = os.fsync
fsync_seen = [0]

def fsync(fd):
    fsync_seen[0] += 1
    result = real_fsync(fd)
    if fsync_seen[0] == {index} and {target!r} == "fsync":
        os.kill(os.getpid(), signal.SIGKILL)
    return result

os.fsync = fsync

real_rename = os.rename
rename_seen = [0]

def rename(*args, **kwargs):
    rename_seen[0] += 1
    result = real_rename(*args, **kwargs)
    if rename_seen[0] == {index} and {target!r} == "rename":
        os.kill(os.getpid(), signal.SIGKILL)
    return result

os.rename = rename

store.save(profile("child"), [])
print("DONE", flush=True)
'''


class SigkillRecoveryCampaignTests(TempRootTestCase):
    """Kill the writer after each accepted barrier; classify from disk."""

    def _run_child(self, code: str) -> subprocess.Popen:
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONPATH": SRC},
        )

    def _finish_child(self, process: subprocess.Popen) -> int:
        """wait, then terminate/wait, then kill/wait; pipes closed always."""
        try:
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            return process.returncode
        finally:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def _fit_admits(self, store: ProfileStore, version: str) -> bool:
        try:
            snapshot = store.coherent_snapshot(PID)
        except (ValueError, OSError):
            return False
        try:
            return version == snapshot.profile.version
        finally:
            snapshot.close()

    def _kill_scenario(self, target: str, index: int,
                       baseline: bool) -> ProfileStore:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        parent_store = _new_store(tmp.name)
        if baseline:
            parent_store.save(_profile(version="base"), [])
        code = _build_kill_child(SRC, tmp.name, target, index, baseline)
        process = self._run_child(code)
        returncode = self._finish_child(process)
        self.assertEqual(-signal.SIGKILL, returncode)
        return parent_store

    def test_kill_after_manifest_temp_fsync_keeps_baseline_committed(self) -> None:
        store = self._kill_scenario("fsync", 1, baseline=True)
        snapshot = store.coherent_snapshot(PID)
        try:
            self.assertEqual("base", snapshot.profile.version)
            self.assertEqual(
                snapshot.manifest["profile_file_sha256"],
                snapshot.hashes["profile_file_sha256"],
            )
        finally:
            snapshot.close()
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_initial_rename_leaves_unrefusable_in_progress(self) -> None:
        store = self._kill_scenario("rename", 1, baseline=False)
        self.assertFalse(self._fit_admits(store, "child"))
        raw = _manifest_bytes(store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_step1_barrier_is_durable_in_progress(self) -> None:
        store = self._kill_scenario("fsync", 2, baseline=False)
        self.assertFalse(self._fit_admits(store, "child"))
        raw = _manifest_bytes(store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_leaf_temp_fsyncs_keeps_old_leaves_intact(self) -> None:
        store = self._kill_scenario("fsync", 4, baseline=False)
        self.assertFalse(self._fit_admits(store, "child"))
        raw = _manifest_bytes(store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_both_leaf_renames_admits_no_mixed_pair(self) -> None:
        store = self._kill_scenario("rename", 3, baseline=False)
        self.assertFalse(self._fit_admits(store, "child"))
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_content_barrier_is_durable_in_progress(self) -> None:
        store = self._kill_scenario("fsync", 5, baseline=False)
        self.assertFalse(self._fit_admits(store, "child"))
        raw = _manifest_bytes(store.directory(PID))
        self.assertEqual("in_progress", _parse_manifest(raw)["state"])
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_committed_rename_before_final_barrier_is_safe(
        self,
    ) -> None:
        store = self._kill_scenario("rename", 4, baseline=False)
        admitted = self._fit_admits(store, "child")
        if not admitted:
            with self.assertRaises((ValueError, OSError)):
                store.coherent_snapshot(PID)
        store.save(_profile(version="retry"), [])
        self.assertTrue(self._fit_admits(store, "retry"))

    def test_kill_after_final_barrier_admits_recovered_commit(self) -> None:
        store = self._kill_scenario("fsync", 7, baseline=False)
        self.assertTrue(self._fit_admits(store, "child"))


# ---------------------------------------------------------------------------
# Same-process SH/EX exclusion through the real flock seam
# ---------------------------------------------------------------------------


class SameProcessExclusionTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [])

    def test_writer_holds_ex_and_nb_snapshot_refuses_until_release(self) -> None:
        ready = threading.Event()
        release = threading.Event()
        original_intercept = store_module._SAVE_LOCK_INTERCEPT
        outcome: dict[str, object] = {}

        def intercept(profile_id: str) -> None:
            ready.set()
            release.wait(timeout=15)

        store_module._SAVE_LOCK_INTERCEPT = intercept
        thread = threading.Thread(target=lambda: None)
        try:

            def writer() -> None:
                try:
                    self.store.save(_profile(version="held"), [])
                    outcome["saved"] = True
                except BaseException as exc:  # surfaced below if it fires
                    outcome["error"] = exc

            thread = threading.Thread(target=writer)
            thread.start()
            deadline = time.monotonic() + 10
            self.assertTrue(ready.wait(timeout=deadline - time.monotonic()))
            self.assertTrue(thread.is_alive())
            started = time.monotonic()
            with self.assertRaises(ValueError) as caught:
                self.store.snapshot(PID, wait=False)
            self.assertIn("generation lock busy", str(caught.exception))
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            release.set()
            thread.join(timeout=15)
            store_module._SAVE_LOCK_INTERCEPT = original_intercept
        self.assertFalse(thread.is_alive())
        self.assertEqual({"saved": True}, outcome)
        loaded, ledger = self.store.load(PID)
        self.assertEqual("held", loaded.version)
        self.assertEqual(0, len(ledger))

    def test_blocking_snapshot_parks_until_writer_releases(self) -> None:
        ready = threading.Event()
        release = threading.Event()
        original_intercept = store_module._SAVE_LOCK_INTERCEPT
        done = threading.Event()
        worker = threading.Thread(target=lambda: None)
        watcher = threading.Thread(target=lambda: None)
        writer_outcome: dict[str, object] = {}
        reader_outcome: dict[str, object] = {}
        try:

            def intercept(profile_id: str) -> None:
                ready.set()
                release.wait(timeout=15)

            def writer() -> None:
                try:
                    self.store.save(_profile(version="parked"), [])
                    writer_outcome["saved"] = True
                except BaseException as exc:
                    writer_outcome["error"] = exc
                release.set()

            def reader() -> None:
                try:
                    snapshot = self.store.snapshot(PID)
                    try:
                        reader_outcome["version"] = snapshot.profile.version
                        snapshot.revalidate()
                    finally:
                        snapshot.close()
                except BaseException as exc:
                    reader_outcome["error"] = exc
                finally:
                    done.set()

            store_module._SAVE_LOCK_INTERCEPT = intercept
            worker = threading.Thread(target=writer)
            worker.start()
            self.assertTrue(ready.wait(timeout=10))
            watcher = threading.Thread(target=reader)
            watcher.start()
            parked_deadline = time.monotonic() + 0.4
            while time.monotonic() < parked_deadline and not done.is_set():
                time.sleep(0.02)
            self.assertFalse(done.is_set())  # SH genuinely parked behind EX
        finally:
            release.set()
            worker.join(timeout=15)
            watcher.join(timeout=15)
            store_module._SAVE_LOCK_INTERCEPT = original_intercept
        self.assertFalse(worker.is_alive())
        self.assertFalse(watcher.is_alive())
        self.assertNotIn("error", writer_outcome)
        self.assertEqual({"saved": True}, writer_outcome)
        self.assertNotIn("error", reader_outcome)
        self.assertEqual("parked", reader_outcome.get("version"))
        loaded, _ledger = self.store.load(PID)
        self.assertEqual("parked", loaded.version)
        self.assertTrue(done.is_set())

    def test_supplemental_direct_flock_blocks_snapshots_load_bearing(self) -> None:
        levels = store_module._open_profile_chain(
            self.store, PID, exclusive=True
        )
        try:
            with self.assertRaises(ValueError) as caught:
                self.store.snapshot(PID, wait=False)
            self.assertIn("generation lock busy", str(caught.exception))
        finally:
            try:
                fcntl.flock(levels[-1].fd, fcntl.LOCK_UN)
            except OSError:
                pass
            for level in reversed(levels):
                level.close()
        snapshot = self.store.snapshot(PID)
        try:
            snapshot.revalidate()
        finally:
            snapshot.close()


# ---------------------------------------------------------------------------
# Cross-process exclusion: poll readiness, bounded cleanup (no readline)
# ---------------------------------------------------------------------------


def _hold_ex_child_code(src: str, root: str, seconds: float) -> str:
    return f'''
import sys, time
sys.path.insert(0, {src!r})
import market_aligner.profiler.store as S
from market_aligner.profiler.schema import CandidateProfile, TrackProfile

PID = {PID!r}

def profile():
    return CandidateProfile(
        profile_id=PID,
        version="child",
        tracks={{"automation": TrackProfile(
            interest=1.0, demonstrated_skill=1.0, confidence=1.0,
            market_readiness=1.0, rationale="child")}},
    )

def intercept(profile_id):
    print("READY", flush=True)
    time.sleep({seconds!r})

S._SAVE_LOCK_INTERCEPT = intercept
store = S.ProfileStore({root!r})
store.save(profile(), [])
print("DONE", flush=True)
'''


def _read_until(stream, token: bytes, timeout: float) -> bytes:
    """Poll-driven token reader bounded by a monotonic deadline."""
    deadline = time.monotonic() + timeout
    buffer = b""
    while token not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"deadline expired waiting for {token!r}")
        readable, _, _ = select.select([stream], [], [], remaining)
        if not readable:
            continue
        chunk = os.read(stream.fileno(), 4096)
        if not chunk:
            raise AssertionError(
                f"stream closed waiting for {token!r}: {buffer!r}"
            )
        buffer += chunk
    return buffer


class CrossProcessExclusionTests(TempRootTestCase):
    def _spawn(self, code: str) -> subprocess.Popen:
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONPATH": SRC},
        )

    def _settle(self, process: subprocess.Popen, timeout: float) -> None:
        """terminate/wait then kill/wait; pipes closed — always in finally."""
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def test_child_ex_blocks_parent_sh_nb_then_child_result_asserted(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [])
        process = self._spawn(_hold_ex_child_code(SRC, self.root, 0.5))
        try:
            output = _read_until(process.stdout, b"READY", timeout=20)
            self.assertIn(b"READY", output)
            self.assertIsNone(process.poll())  # demonstrably still holding EX
            started = time.monotonic()
            with self.assertRaises(ValueError) as caught:
                store.snapshot(PID, wait=False)
            self.assertIn("generation lock busy", str(caught.exception))
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertIn(b"DONE", _read_until(process.stdout, b"DONE", 20))
        finally:
            self._settle(process, timeout=25)
        self.assertEqual(0, process.returncode)
        loaded, _ = store.load(PID)
        self.assertEqual("child", loaded.version)

    def test_parent_blocking_sh_parks_until_child_releases(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [])
        process = self._spawn(_hold_ex_child_code(SRC, self.root, 1.0))
        done = threading.Event()
        watcher = threading.Thread(target=lambda: None)
        try:
            self.assertIn(b"READY", _read_until(process.stdout, b"READY", 20))

            def blocking_reader() -> None:
                snapshot = store.snapshot(PID)
                try:
                    snapshot.revalidate()
                finally:
                    snapshot.close()
                done.set()

            watcher = threading.Thread(target=blocking_reader)
            watcher.start()
            parked_deadline = time.monotonic() + 0.3
            while time.monotonic() < parked_deadline and not done.is_set():
                time.sleep(0.02)
            self.assertFalse(done.is_set())
            self.assertIn(b"DONE", _read_until(process.stdout, b"DONE", 20))
        finally:
            self._settle(process, timeout=25)
            watcher.join(timeout=20)
        self.assertTrue(done.is_set())
        self.assertEqual(0, process.returncode)
        loaded, _ = store.load(PID)
        self.assertEqual("child", loaded.version)

    def test_terminate_release_reclaims_lock_with_cleanup(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(), [])
        process = self._spawn(_hold_ex_child_code(SRC, self.root, 30))
        try:
            self.assertIn(b"READY", _read_until(process.stdout, b"READY", 20))
            with self.assertRaises(ValueError):
                store.snapshot(PID, wait=False)
        finally:
            self._settle(process, timeout=5)
        self.assertIsNotNone(process.poll())
        snapshot = store.snapshot(PID)  # OS reclaims flock on child death
        try:
            snapshot.revalidate()
        finally:
            snapshot.close()


# ---------------------------------------------------------------------------
# Resource bounds: exact maxima reach parsing; max+1 refuses (§6)
# ---------------------------------------------------------------------------


class ResourceBoundTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [_evidence()])
        self.directory = self.store.directory(PID)

    def test_exact_maximum_profile_yaml_reaches_parsing(self) -> None:
        _drop_manifest(self.store)
        base = (self.directory / PROFILE_NAME).read_bytes()
        deficit = MAX_PROFILE_BYTES - len(base) - 3
        self.assertGreater(deficit, 0)
        padded = base + b"# " + b"p" * deficit + b"\n"
        self.assertEqual(MAX_PROFILE_BYTES, len(padded))
        _write_leaf(self.store, PROFILE_NAME, padded)
        snapshot = self.store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertEqual(
                MAX_PROFILE_BYTES, len(snapshot._bytes[PROFILE_NAME])
            )
            snapshot.revalidate()
        finally:
            snapshot.close()

    def test_profile_over_maximum_refuses_before_parsing(self) -> None:
        _drop_manifest(self.store)
        _write_leaf(self.store, PROFILE_NAME, b"x" * (MAX_PROFILE_BYTES + 1))
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("exceeds", str(caught.exception))

    def _items_totalling(self, target: int) -> list:
        # Filler rows carry a fixed-width id and a fixed-size claim; the final
        # row's claim is padded so the serialized ledger hits `target` exactly.
        probe = len(_row(_evidence("ev00000", "a"))) + 1  # row + newline
        filler_claim = 512
        per_row = probe - 1 + filler_claim
        count = max(0, (target - 4096) // per_row)
        ordered = sorted(
            (
                _evidence(f"ev{index:05d}", "a" * filler_claim)
                for index in range(count)
            ),
            key=lambda item: item.evidence_id,
        )
        body = "".join(_row(item) + "\n" for item in ordered)
        last_probe = _row(_evidence("zzzz-last", "a"))
        pad = target - len(body) - len(last_probe)  # includes trailing newline
        self.assertGreater(pad, 0)
        last = _evidence("zzzz-last", "a" * pad)
        return ordered + [last]

    def test_exact_maximum_evidence_roundtrips_through_save(self) -> None:
        items = self._items_totalling(MAX_EVIDENCE_BYTES)
        self.store.save(_profile(), items)
        self.assertEqual(
            MAX_EVIDENCE_BYTES,
            os.path.getsize(self.directory / EVIDENCE_NAME),
        )
        _, loaded = self.store.load(PID)
        self.assertEqual(len(items), len(loaded))
        snapshot = self.store.coherent_snapshot(PID)
        try:
            self.assertEqual(
                MAX_EVIDENCE_BYTES, len(snapshot._bytes[EVIDENCE_NAME])
            )
        finally:
            snapshot.close()

    def test_evidence_over_maximum_refuses_on_save_and_on_read(self) -> None:
        items = self._items_totalling(MAX_EVIDENCE_BYTES + 1)
        baseline = _tree_digest(pathlib.Path(self.root))
        with self.assertRaises(ValueError) as caught:
            self.store.save(_profile(), items)
        self.assertIn("exceeds its bound", str(caught.exception))
        self.assertEqual(baseline, _tree_digest(pathlib.Path(self.root)))
        _drop_manifest(self.store)
        ledger = "".join(_row(item) + "\n" for item in items).encode("utf-8")
        _write_leaf(self.store, EVIDENCE_NAME, ledger)
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("exceeds", str(caught.exception))

    def test_large_evidence_publication_roundtrip(self) -> None:
        big_items = [
            _evidence(f"big-{index:04d}", "context " * 200)
            for index in range(1200)
        ]
        total = sum(len(_row(item)) + 1 for item in big_items)
        self.assertGreater(total, MAX_PROFILE_BYTES)
        self.assertLessEqual(total, MAX_EVIDENCE_BYTES)
        self.store.save(_profile(), big_items)
        _, loaded = self.store.load(PID)
        self.assertEqual(len(big_items), len(loaded))
        snapshot = self.store.coherent_snapshot(PID)
        try:
            self.assertGreater(len(snapshot._bytes[EVIDENCE_NAME]), 1_000_000)
        finally:
            snapshot.close()

    def test_exactly_ten_thousand_rows_pass_end_to_end(self) -> None:
        items = [_evidence(f"row-{index:05d}") for index in range(10_000)]
        self.store.save(_profile(), items)
        _, loaded = self.store.load(PID)
        self.assertEqual(MAX_EVIDENCE_ROWS, len(loaded))
        snapshot = self.store.coherent_snapshot(PID)
        try:
            framed = snapshot._bytes[EVIDENCE_NAME].split(b"\n")[:-1]
            self.assertEqual(MAX_EVIDENCE_ROWS, len(framed))
        finally:
            snapshot.close()

    def test_ten_thousand_and_one_rows_refuse_before_validation(self) -> None:
        items = [_evidence(f"row-{index:05d}") for index in range(10_001)]
        baseline = _tree_digest(pathlib.Path(self.root))
        with self.assertRaises(ValueError) as caught:
            self.store.save(_profile(), items)
        self.assertIn("at most", str(caught.exception))
        self.assertEqual(baseline, _tree_digest(pathlib.Path(self.root)))

    def test_leaf_side_row_boundary_exactly_10000_passes_10001_refuses(
        self,
    ) -> None:
        _drop_manifest(self.store)
        ok = "".join(
            _row(_evidence(f"leaf-{index:05d}")) + "\n"
            for index in range(10_000)
        )
        _write_leaf(self.store, EVIDENCE_NAME, ok.encode("utf-8"))
        snapshot = self.store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertEqual(MAX_EVIDENCE_ROWS, len(snapshot.evidence_ledger))
        finally:
            snapshot.close()
        over = ok + _row(_evidence("leaf-over")) + "\n"
        _write_leaf(self.store, EVIDENCE_NAME, over.encode("utf-8"))
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("nonblank rows", str(caught.exception))

    def test_empty_evidence_is_valid_and_rereads_exact(self) -> None:
        _drop_manifest(self.store)
        _write_leaf(self.store, EVIDENCE_NAME, b"")
        snapshot = self.store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertEqual(b"", snapshot._bytes[EVIDENCE_NAME])
            self.assertEqual([], snapshot.evidence_ledger)
            snapshot.revalidate()
        finally:
            snapshot.close()


class EvidenceFramingTests(TempRootTestCase):
    """Literal-LF framing only; escaped prose controls never delimit."""

    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [_evidence()])
        _drop_manifest(self.store)

    def _raw_leaf_snapshot_refuses(self, raw: bytes, message: str) -> None:
        _write_leaf(self.store, EVIDENCE_NAME, raw)
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn(message, str(caught.exception))

    def test_vertical_tab_raw_byte_refuses(self) -> None:
        row = _row(_evidence()).encode("utf-8")
        self._raw_leaf_snapshot_refuses(row + b"\x0b" + row + b"\n", "raw control")

    def test_form_feed_raw_byte_refuses(self) -> None:
        row = _row(_evidence()).encode("utf-8")
        self._raw_leaf_snapshot_refuses(row + b"\x0c" + row + b"\n", "raw control")

    def test_nul_raw_byte_refuses(self) -> None:
        row = _row(_evidence()).encode("utf-8").replace(
            b"Shipped", b"Sh\x00ipped"
        )
        self._raw_leaf_snapshot_refuses(row + b"\n", "raw control")

    def test_delete_raw_byte_refuses(self) -> None:
        row = _row(_evidence()).encode("utf-8")
        self._raw_leaf_snapshot_refuses(row + b"\x7f\n", "raw control")

    def test_raw_tab_and_carriage_return_refuse(self) -> None:
        row = _row(_evidence()).encode("utf-8")
        self._raw_leaf_snapshot_refuses(
            row.replace(b'"claim"', b'"cla\tim"') + b"\n", "raw control"
        )
        self._raw_leaf_snapshot_refuses(
            row.replace(b"Shipped", b"Sh\rXipped") + b"\n", "raw control"
        )

    def test_escaped_ht_lf_cr_decode_inside_claim_only(self) -> None:
        item = EvidenceItem(
            evidence_id="esc-1",
            kind="project",
            claim="tab\tnewline\ncarriage\rreturn",
            source_ref="repo/x",
            status="verified",
            confidence=0.5,
        )
        manual = json.dumps(asdict(item), ensure_ascii=False, sort_keys=True)
        manual = manual.replace("\t", "\\t").replace("\n", "\\n").replace(
            "\r", "\\r"
        )
        payload = (manual + "\n").encode("utf-8")  # literal LF frame only
        _write_leaf(self.store, EVIDENCE_NAME, payload)
        snapshot = self.store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertEqual(1, len(snapshot.evidence_ledger))
            decoded = snapshot.evidence_ledger[0].claim
            self.assertIn("\t", decoded)
            self.assertIn("\n", decoded)
            self.assertIn("\r", decoded)
        finally:
            snapshot.close()

    def test_escaped_control_in_nonclaim_field_refuses(self) -> None:
        data = asdict(_evidence("esc-2"))
        data["source_ref"] = "repo\x07bell"
        manual = json.dumps(data, ensure_ascii=False, sort_keys=True)
        manual = manual.replace("\x07", "\\u0007")
        _write_leaf(
            self.store, EVIDENCE_NAME, (manual + "\n").encode("utf-8")
        )
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("forbidden", str(caught.exception))

    def test_escaped_vt_in_claim_is_not_allowed_prose(self) -> None:
        data = asdict(_evidence("esc-3"))
        data["claim"] = "bad\x0bvt"
        manual = json.dumps(data, ensure_ascii=False, sort_keys=True)
        manual = manual.replace("\x0b", "\\u000b")
        _write_leaf(
            self.store, EVIDENCE_NAME, (manual + "\n").encode("utf-8")
        )
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("forbidden", str(caught.exception))

    # -- final-LF framing rule (enforced before splitting/parsing) ----------

    def test_missing_final_literal_lf_refuses_before_parsing(self) -> None:
        row = _row(_evidence("nolf", "claim")).encode("utf-8")
        self._raw_leaf_snapshot_refuses(row, "final literal LF")

    def test_empty_evidence_bytes_are_valid_legacy(self) -> None:
        _write_leaf(self.store, EVIDENCE_NAME, b"")
        snapshot = self.store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertTrue(snapshot.legacy_unsealed)
            self.assertEqual([], snapshot.evidence_ledger)
            self.assertEqual({}, snapshot.evidence)
        finally:
            snapshot.close()

    def test_compatible_historical_whitespace_rows_accepted(self) -> None:
        row = _row(_evidence("ws-1", "claim")).encode("utf-8")
        _write_leaf(self.store, EVIDENCE_NAME, b"  " + row + b"   \n")
        snapshot = self.store.snapshot(PID, require_committed_generation=False)
        try:
            self.assertEqual(1, len(snapshot.evidence_ledger))
            self.assertEqual("ws-1", snapshot.evidence_ledger[0].evidence_id)
        finally:
            snapshot.close()

    # -- strict JSON objective refusals (via the public parse path) ---------

    def test_duplicate_json_key_in_row_refuses(self) -> None:
        row = _row(_evidence("dup-1", "claim"))
        poisoned = row.replace("{", '{"confidence":0.5,', 1) + "\n"
        self.assertIn('"confidence":0.5,', poisoned)
        _write_leaf(self.store, EVIDENCE_NAME, poisoned.encode("utf-8"))
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("duplicate JSON key", str(caught.exception))
        # Distinguishing power: permissive json.loads would silently take the
        # LAST confidence and accept this ledger; the assertion above fails
        # if _strict_json_loads is ever replaced by plain json.loads.

    def test_nan_constant_in_row_refuses(self) -> None:
        row = _row(_evidence("nan-1", "claim"))
        poisoned = (
            row.replace('"confidence": 0.9', '"confidence": NaN') + "\n"
        ).encode("utf-8")
        self.assertIn(b'"confidence": NaN', poisoned)
        _write_leaf(self.store, EVIDENCE_NAME, poisoned)
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("nonfinite JSON constant", str(caught.exception))

    def test_infinity_constant_in_row_refuses(self) -> None:
        row = _row(_evidence("inf-1", "claim"))
        poisoned = (
            row.replace('"confidence": 0.9', '"confidence": Infinity') + "\n"
        ).encode("utf-8")
        self.assertIn(b'"confidence": Infinity', poisoned)
        _write_leaf(self.store, EVIDENCE_NAME, poisoned)
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("nonfinite JSON constant", str(caught.exception))

    def test_negative_infinity_constant_in_row_refuses(self) -> None:
        row = _row(_evidence("ninf-1", "claim"))
        poisoned = (
            row.replace('"confidence": 0.9', '"confidence": -Infinity')
            + "\n"
        ).encode("utf-8")
        self.assertIn(b'"confidence": -Infinity', poisoned)
        _write_leaf(self.store, EVIDENCE_NAME, poisoned)
        with self.assertRaises(ValueError) as caught:
            self.store.snapshot(PID, require_committed_generation=False)
        self.assertIn("nonfinite JSON constant", str(caught.exception))

    def test_invalid_utf8_bytes_in_row_refuse(self) -> None:
        row = _row(_evidence("bad-utf8", "claim")).encode("utf-8")
        poisoned = row.replace(b'"claim"', b'"cla\xff\xfeim"') + b"\n"
        _write_leaf(self.store, EVIDENCE_NAME, poisoned)
        with self.assertRaises(ValueError):
            self.store.snapshot(PID, require_committed_generation=False)


# ---------------------------------------------------------------------------
# Retained-descriptor revalidation and substitution negatives (§6/§21)
# ---------------------------------------------------------------------------


class RevalidationDriftTests(TempRootTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(version="v1"), [_evidence()])

    def _open(self) -> CoherentProfileSnapshot:
        snapshot = self.store.coherent_snapshot(PID)
        self.addCleanup(snapshot.close)
        return snapshot

    def test_same_size_inplace_rewrite_detected_offset_untouched(self) -> None:
        snapshot = self._open()
        fd = snapshot.leaf_fd(EVIDENCE_NAME)
        os.lseek(fd, 3, os.SEEK_SET)
        attacker = os.open(
            EVIDENCE_NAME,
            os.O_WRONLY | os.O_NOFOLLOW,
            dir_fd=snapshot._directory.fd,
        )
        try:
            mutated = bytearray(snapshot._bytes[EVIDENCE_NAME])
            mutated[-2] = ord("X") if mutated[-2] != ord("X") else ord("Y")
            os.pwrite(attacker, bytes(mutated), 0)
            os.fsync(attacker)
        finally:
            os.close(attacker)
        with self.assertRaises(ValueError) as caught:
            snapshot.revalidate()
        self.assertIn("drift", str(caught.exception).lower())
        self.assertEqual(3, os.lseek(fd, 0, os.SEEK_CUR))

    def test_repeated_revalidate_preserves_offset_independence(self) -> None:
        snapshot = self._open()
        fd = snapshot.leaf_fd(PROFILE_NAME)
        os.lseek(fd, 7, os.SEEK_SET)
        for _ in range(4):
            snapshot.revalidate()
            self.assertEqual(7, os.lseek(fd, 0, os.SEEK_CUR))

    def test_leaf_inode_replacement_detected(self) -> None:
        snapshot = self._open()
        _write_leaf(self.store, EVIDENCE_NAME, b'{"same":"size"}\n')
        with self.assertRaises(ValueError):
            snapshot.revalidate()

    def test_leaf_symlink_swap_detected(self) -> None:
        snapshot = self._open()
        directory = self.store.directory(PID)
        os.unlink(directory / PROFILE_NAME)
        os.symlink(".decoy.yaml", directory / PROFILE_NAME)
        try:
            with self.assertRaises((ValueError, OSError)):
                snapshot.revalidate()
        finally:
            os.unlink(directory / PROFILE_NAME)

    def test_leaf_hardlink_drift_detected(self) -> None:
        snapshot = self._open()
        directory = self.store.directory(PID)
        os.link(directory / EVIDENCE_NAME, directory / ".alias-evd")
        try:
            with self.assertRaises(ValueError):
                snapshot.revalidate()
        finally:
            os.unlink(directory / ".alias-evd")

    def test_leaf_mode_drift_detected(self) -> None:
        snapshot = self._open()
        os.chmod(self.store.directory(PID) / EVIDENCE_NAME, 0o644)
        with self.assertRaises(ValueError):
            snapshot.revalidate()

    def test_manifest_replacement_detected(self) -> None:
        snapshot = self._open()
        _write_leaf(
            self.store,
            MANIFEST_NAME,
            _expected_manifest("committed", "0" * 64, "1" * 64),
        )
        with self.assertRaises(ValueError):
            snapshot.revalidate()

    def test_profile_directory_replacement_detected(self) -> None:
        snapshot = self._open()
        profiles = self.store.paths.profiles
        moved = profiles / ".moved-generation"
        os.rename(profiles / PID, moved)
        replacement = profiles / PID
        replacement.mkdir(mode=0o700)
        for name in (PROFILE_NAME, EVIDENCE_NAME, MANIFEST_NAME):
            os.rename(moved / name, replacement / name)
        try:
            with self.assertRaises(ValueError):
                snapshot.revalidate()
        finally:
            shutil.rmtree(replacement)
            os.rename(moved, profiles / PID)

    def test_profiles_directory_replacement_detected(self) -> None:
        snapshot = self._open()
        root = self.store.paths.root
        moved = root / ".profiles-moved"
        os.rename(root / "profiles", moved)
        replacement = root / "profiles"
        replacement.mkdir(mode=0o700)
        os.rename(moved / PID, replacement / PID)
        try:
            with self.assertRaises(ValueError):
                snapshot.revalidate()
        finally:
            snapshot.close()
            shutil.rmtree(replacement)
            os.rename(moved, root / "profiles")

    def test_data_home_replacement_detected_then_restored(self) -> None:
        snapshot = self._open()
        root_path = pathlib.Path(self.store.paths.root)
        parent = root_path.parent
        moved = parent / ".data-home-moved"
        os.rename(root_path, moved)
        replacement = parent / root_path.name
        replacement.mkdir(mode=0o700)
        try:
            with self.assertRaises(ValueError):
                snapshot.revalidate()
        finally:
            snapshot.close()
            replacement.rmdir()
            os.rename(moved, root_path)
        fresh = self.store.coherent_snapshot(PID)
        try:
            self.assertEqual("v1", fresh.profile.version)
        finally:
            fresh.close()

    def test_locator_parent_sibling_tolerated(self) -> None:
        snapshot = self._open()
        sibling = (
            pathlib.Path(self.store.paths.root).parent / ".unrelated-sibling"
        )
        sibling.write_text("innocent")
        try:
            snapshot.revalidate()  # locator-only level ignores unrelated names
        finally:
            sibling.unlink()

    def test_data_home_nlink_drift_rejected(self) -> None:
        snapshot = self._open()
        added = self.store.paths.root / ".extra-subdir"
        added.mkdir(mode=0o700)
        try:
            with self.assertRaises(ValueError):
                snapshot.revalidate()
        finally:
            added.rmdir()

    def test_below_data_home_nlink_drift_rejected(self) -> None:
        snapshot = self._open()
        added = self.store.paths.profiles / ".extra-profiles-subdir"
        added.mkdir(mode=0o700)
        try:
            with self.assertRaises(ValueError):
                snapshot.revalidate()
        finally:
            added.rmdir()


# ---------------------------------------------------------------------------
# Fifty-iteration /dev/fd stability campaigns (§21 descriptor ownership)
# ---------------------------------------------------------------------------


@unittest.skipUnless(
    os.path.isdir("/dev/fd"),
    "fd-count unobservable: /dev/fd unavailable on this platform "
    "(named environment-qualified skip)",
)
class FdStabilityCampaignTests(TempRootTestCase):
    ITERATIONS = 50

    def setUp(self) -> None:
        super().setUp()
        self.store = _new_store(self.root)
        self.store.save(_profile(), [_evidence()])
        self.directory = self.store.directory(PID)
        self.original_evidence = (self.directory / EVIDENCE_NAME).read_bytes()

    def _campaign(self, action) -> None:
        before = _fd_count()
        for _ in range(self.ITERATIONS):
            action()
        self.assertEqual(before, _fd_count())

    def _refuse_snapshot(self) -> None:
        with self.assertRaises((ValueError, OSError)):
            self.store.snapshot(PID, wait=False)

    def test_repeated_unsafe_directory_mode_refusals_are_fd_stable(self) -> None:
        profiles = self.store.paths.profiles
        os.chmod(profiles, 0o755)
        try:
            self._campaign(self._refuse_snapshot)
        finally:
            os.chmod(profiles, 0o700)

    def test_repeated_unsafe_leaf_mode_refusals_are_fd_stable(self) -> None:
        os.chmod(self.directory / EVIDENCE_NAME, 0o644)
        try:
            self._campaign(self._refuse_snapshot)
        finally:
            os.chmod(self.directory / EVIDENCE_NAME, 0o600)

    def test_repeated_symlink_leaf_refusals_are_fd_stable(self) -> None:
        os.unlink(self.directory / EVIDENCE_NAME)
        os.symlink(".decoy.jsonl", self.directory / EVIDENCE_NAME)
        try:
            self._campaign(self._refuse_snapshot)
        finally:
            os.unlink(self.directory / EVIDENCE_NAME)
            _write_leaf(self.store, EVIDENCE_NAME, self.original_evidence)

    def test_repeated_oversize_leaf_refusals_are_fd_stable(self) -> None:
        _write_leaf(self.store, PROFILE_NAME, b"z" * (MAX_PROFILE_BYTES + 1))
        self._campaign(self._refuse_snapshot)

    def test_repeated_malformed_manifest_refusals_are_fd_stable(self) -> None:
        _write_leaf(self.store, MANIFEST_NAME, b"{malformed")
        self._campaign(self._refuse_snapshot)

    def test_replaced_manifest_campaign_is_fd_stable(self) -> None:
        _write_leaf(
            self.store,
            MANIFEST_NAME,
            _expected_manifest("committed", "0" * 64, "1" * 64),
        )
        self._campaign(self._refuse_snapshot)

    def test_repeated_successful_saves_are_fd_stable(self) -> None:
        self._campaign(lambda: self.store.save(_profile(version="loop"), []))

    def test_repeated_faulted_saves_are_fd_stable_then_retry_succeeds(self) -> None:
        cause = OSError("campaign-fault")

        def faulted() -> None:
            with store_module._fault_at(BOUNDARY_STEP1_BARRIER, cause):
                with self.assertRaises(DurableInProgressSaveFailed):
                    self.store.save(_profile(version="faulted"), [])

        self._campaign(faulted)
        self.store.save(_profile(version="post-campaign"), [])
        snapshot = self.store.coherent_snapshot(PID)
        try:
            self.assertEqual("post-campaign", snapshot.profile.version)
        finally:
            snapshot.close()


# ---------------------------------------------------------------------------
# API surface: save returns None; load/list compatibility (§21 positive)
# ---------------------------------------------------------------------------


class ApiSurfaceTests(TempRootTestCase):
    def test_save_annotation_is_none_and_call_returns_none(self) -> None:
        hints = typing.get_type_hints(ProfileStore.save)
        self.assertIs(type(None), hints.get("return"))
        store = _new_store(self.root)
        self.assertIsNone(store.save(_profile(), [_evidence()]))

    def test_load_and_list_compatibility_across_stores(self) -> None:
        store = _new_store(self.root)
        store.save(_profile(version="compat"), [_evidence("only-one")])
        loaded, ledger = store.load(PID)
        self.assertEqual("compat", loaded.version)
        self.assertEqual(["only-one"], sorted(ledger))
        self.assertEqual([PID], store.list_profile_ids())
        other = _new_store(self.root)
        other.save(_profile(version="second", pid=OTHER_PID), [])
        self.assertEqual([PID, OTHER_PID], other.list_profile_ids())


# ---------------------------------------------------------------------------
# FIT-001 Stage D Part 1: retained-descriptor fd hygiene + substitution
# ---------------------------------------------------------------------------


class RetainedDescriptorAuthorityTests(TempRootTestCase):
    """Stage D Part-1 gates: fd hygiene, substitution refusals, seam reuse."""

    def _private_tree(self) -> pathlib.Path:
        data = pathlib.Path(self.root) / "data_home"
        inbox = data / "state" / "processing-inbox"
        inbox.mkdir(parents=True)
        for directory in (data, data / "state", inbox):
            os.chmod(directory, 0o700)
        return data

    def _seed_leaf(self, data: pathlib.Path) -> pathlib.Path:
        leaf = data / "state" / "processing-inbox" / ("a" * 64 + ".json")
        leaf.write_bytes(b'{"k":1}\n')
        os.chmod(leaf, 0o600)
        return leaf

    def _authority(self, data: pathlib.Path):
        descriptors = processing_module._DescriptorSet()
        try:
            root, _state, inbox = processing_module.open_processing_authority(
                data, descriptors
            )
        except BaseException:
            descriptors.close()
            raise
        self.addCleanup(descriptors.close)
        return descriptors, root, inbox

    def test_repeated_invalid_directory_campaign_keeps_fd_baseline(self) -> None:
        # Create every fixture ONCE; probe each 50 times without recreation.
        missing = pathlib.Path(self.root) / "missing_home"
        loose = pathlib.Path(self.root) / "loose"
        loose.mkdir()
        os.chmod(loose, 0o755)
        target = pathlib.Path(self.root) / "real_target"
        target.mkdir()
        os.chmod(target, 0o700)
        link = pathlib.Path(self.root) / "linked_home"
        link.symlink_to(target)

        baseline = _fd_count()
        for _ in range(50):
            for probe in (missing, loose, link):
                descriptors = processing_module._DescriptorSet()
                try:
                    with self.assertRaises((ValueError, OSError)):
                        processing_module._open_chain_to(probe, descriptors)
                finally:
                    descriptors.close()
        self.assertEqual(baseline, _fd_count())

    def test_repeated_invalid_leaf_campaign_keeps_fd_baseline(self) -> None:
        data = self._private_tree()
        _, _root, inbox = self._authority(data)

        bad_mode = data / "state" / "processing-inbox" / ("b" * 64 + ".json")
        bad_mode.write_bytes(b"x\n")
        os.chmod(bad_mode, 0o644)

        hardlinked = data / "state" / "processing-inbox" / ("c" * 64 + ".json")
        hardlinked.write_bytes(b"x\n")
        os.chmod(hardlinked, 0o600)
        os.link(hardlinked, hardlinked.parent / "witness.json")

        oversized = data / "state" / "processing-inbox" / ("d" * 64 + ".json")
        oversized.write_bytes(b"y" * (processing_module.MAX_ENVELOPE_BYTES + 1))
        os.chmod(oversized, 0o600)

        symlinked = data / "state" / "processing-inbox" / ("e" * 64 + ".json")
        symlinked.symlink_to(bad_mode)

        missing_name = "f" * 64 + ".json"

        baseline = _fd_count()
        for _ in range(50):
            for name in (
                bad_mode.name,
                hardlinked.name,
                oversized.name,
                symlinked.name,
                missing_name,
            ):
                with self.assertRaises((ValueError, OSError)):
                    processing_module._RetainedLeaf(
                        inbox, name, maximum=processing_module.MAX_ENVELOPE_BYTES
                    )
        self.assertEqual(baseline, _fd_count())

    def test_leaf_growth_shrink_unlink_and_swap_refuse(self) -> None:
        data = self._private_tree()
        leaf_path = self._seed_leaf(data)
        _, _root, inbox = self._authority(data)
        leaf = processing_module._RetainedLeaf(
            inbox, leaf_path.name, maximum=processing_module.MAX_ENVELOPE_BYTES
        )
        self.assertEqual(b'{"k":1}\n', leaf.data)

        with open(leaf_path, "ab") as handle:
            handle.write(b"extra")
        with self.assertRaises(ValueError):
            leaf.revalidate(inbox)

        with open(leaf_path, "wb") as handle:
            handle.write(b"")
        with self.assertRaises(ValueError):
            leaf.revalidate(inbox)

        replacement = pathlib.Path(self.root) / "replacement.json"
        replacement.write_bytes(b'{"k":2}\n')
        os.chmod(replacement, 0o600)
        os.replace(replacement, leaf_path)
        with self.assertRaises(ValueError):
            leaf.revalidate(inbox)

        leaf_path.unlink()
        with self.assertRaises(ValueError):
            leaf.revalidate(inbox)

        leaf.close()

    def test_sibling_creation_tolerated_but_private_drift_refused(self) -> None:
        data = self._private_tree()
        descriptors, root, inbox = self._authority(data)

        # Unrelated sibling creation beside data_home is locator-only and
        # must not disturb the retained authority.
        sibling = data.parent / "unrelated-sibling"
        sibling.mkdir()
        os.chmod(sibling, 0o755)
        descriptors.revalidate_directories()

        # Strict-mode drift on data_home itself is rejected by the canonical
        # revalidate and restores cleanly afterwards.
        os.chmod(data, 0o755)
        with self.assertRaises(ValueError):
            descriptors.revalidate_directories()
        os.chmod(data, 0o700)
        descriptors.revalidate_directories()

        # Mode drift on a strict private level refuses.
        state_path = data / "state"
        os.chmod(state_path, 0o755)
        with self.assertRaises(ValueError):
            descriptors.revalidate_directories()
        os.chmod(state_path, 0o700)
        descriptors.revalidate_directories()

        # Identity swap of the inbox directory refuses even at exact mode.
        moved = data / "state" / "inbox-moved"
        os.rename(data / "state" / "processing-inbox", moved)
        fresh = data / "state" / "processing-inbox"
        fresh.mkdir()
        os.chmod(fresh, 0o700)
        del inbox
        with self.assertRaises(ValueError):
            descriptors.revalidate_directories()
        shutil.rmtree(moved)

    def test_non_fresh_set_refuses_second_anchor_without_leak(self) -> None:
        data = self._private_tree()
        baseline = _fd_count()
        descriptors, _root, _inbox = self._authority(data)
        held = _fd_count()

        # Second anchor on the same non-fresh set refuses before opening.
        with self.assertRaises(ValueError):
            processing_module._open_chain_to(data, descriptors)
        with self.assertRaises(ValueError):
            processing_module.open_processing_authority(data, descriptors)

        # The original ownership remains fully valid after both refusals.
        descriptors.revalidate_directories()
        self.assertEqual(held, _fd_count())

        descriptors.close()
        self.assertEqual(baseline, _fd_count())

        # Control: a fresh set accepts the same authority again.
        fresh_descriptors = processing_module._DescriptorSet()
        try:
            fresh_root, _s, _i = processing_module.open_processing_authority(
                data, fresh_descriptors
            )
            fresh_root.revalidate()
        finally:
            fresh_descriptors.close()
        self.assertEqual(baseline, _fd_count())

    def test_authority_helper_rolls_back_call_local_ownership_on_failure(self) -> None:
        data = self._private_tree()
        # A non-private inbox makes the composed authority fail AFTER the
        # canonical root anchored; the helper must close everything itself.
        os.chmod(data / "state" / "processing-inbox", 0o755)
        baseline = _fd_count()
        descriptors = processing_module._DescriptorSet()
        try:
            with self.assertRaises(ValueError):
                processing_module.open_processing_authority(data, descriptors)
        finally:
            descriptors.close()
        self.assertEqual(baseline, _fd_count())
        self.assertIsNone(descriptors.root)

    def test_valid_chain_holds_exact_bytes_then_releases_fds(self) -> None:
        data = self._private_tree()
        leaf_path = self._seed_leaf(data)
        before = _fd_count()
        descriptors, root, inbox = self._authority(data)
        leaf = processing_module._RetainedLeaf(
            inbox, leaf_path.name, maximum=processing_module.MAX_ENVELOPE_BYTES
        )
        descriptors.push_leaf(leaf)
        held = _fd_count()
        self.assertGreater(held, before)
        self.assertEqual(b'{"k":1}\n', leaf.data)
        leaf.revalidate(inbox)
        descriptors.revalidate_directories()
        descriptors.close()
        self.assertEqual(before, _fd_count())


class StageDEnvelopeAuthorityTests(TempRootTestCase):
    """Stage D Part-2 gates: retained envelope authority + closed schema."""

    LLM_VERSION = "market-aligner.llm.v1"
    ENVELOPE_VERSION = "market-aligner.processing-envelope.v1"
    PROFILE_ID = "prf_" + "a" * 32
    JOB_KEY = "boards.example:j-1"
    DELETE = object()

    # ------------------------------------------------------------ fixtures

    def _tree(self) -> pathlib.Path:
        data = pathlib.Path(self.root) / "data_home"
        inbox = data / "state" / "processing-inbox"
        inbox.mkdir(parents=True)
        for directory in (data, data / "state", inbox):
            os.chmod(directory, 0o700)
        return data

    def _extraction_output(self) -> dict:
        return {
            "source_content_sha256": "a" * 64,
            "title": "Senior Backend Engineer",
            "company": "",
            "location": "",
            "description": "Build services.\nShip reliably.",
            "responsibilities": ["Own services end to end"],
            "required_skills": ["Python"],
            "preferred_skills": [],
            "required_qualifications": ["5 years"],
            "preferred_qualifications": [],
            "work_authorisation": [],
            "contract_type": "",
            "seniority": "",
            "remote_policy": "",
            "extraction_confidence": 0.9,
            "unknown_fields": ["legacy_field"],
            "contract_version": self.LLM_VERSION,
        }

    def _receipt(self, task: str, output: dict, *, output_sha: str | None = None) -> dict:
        return {
            "receipt_id": "rcpt-0001",
            "task": task,
            "model": "test-model",
            "prompt_version": "pv-1",
            "input_sha256": "1" * 64,
            "output_sha256": output_sha
            or hashlib.sha256(
                processing_module.canonical_json(output).encode("utf-8")
            ).hexdigest(),
            "created_at": "2026-08-25T00:00:00Z",
            "contract_version": self.LLM_VERSION,
        }

    def _alignment_output(self) -> dict:
        return {
            "profile_id": self.PROFILE_ID,
            "profile_version": "2024-01",
            "job_key": self.JOB_KEY,
            "matches": [
                {
                    "requirement": "Own services end to end",
                    "evidence_ids": ["ev-1", "ev-2"],
                    "strength": 0.75,
                    "rationale": "Direct ownership evidence exists.",
                }
            ],
            "missing_requirements": ["Kubernetes operations"],
            "technical_alignment": 0.6,
            "evidence_match": 0.5,
            "confidence": 0.7,
            "unknowns": [],
            "contract_version": self.LLM_VERSION,
        }

    def _expected_score(self) -> dict:
        return {
            "profile_id": self.PROFILE_ID,
            "job_key": self.JOB_KEY,
            "track": "backend",
            "fit": 0.42,
            "opportunity": 0.555,
            "final": 48.75,
            "fit_status": "uncalibrated",
            "parameters_hash": processing_module.ScoringParams().parameters_hash,
            "fit_subscores": {
                "interest": 0.4,
                "demonstrated_skill": 0.5,
                "market_readiness": 0.3,
                "technical_alignment": 0.6,
                "evidence_match": 0.5,
            },
            "opportunity_subscores": {
                "market_demand": 0.0,
                "accessibility": 1.0,
                "growth_potential": 0.0,
            },
        }

    def _golden_payload(self, data: pathlib.Path) -> dict:
        extraction = self._extraction_output()
        alignment = self._alignment_output()
        closure = {"/cfg/product.toml": "b" * 64}
        return {
            "schema_version": self.ENVELOPE_VERSION,
            "operation_id": "op-12345678",
            "job_key": self.JOB_KEY,
            "profile_id": self.PROFILE_ID,
            "profile_version": "2024-01",
            "track": "backend",
            "config": {
                "source_path": "/cfg/product.toml",
                "source_file_sha256": "b" * 64,
                "closure_files": closure,
                "closure_sha256": hashlib.sha256(
                    processing_module.canonical_json(closure).encode("utf-8")
                ).hexdigest(),
                "semantic_sha256": "c" * 64,
            },
            "databases": self._database_bindings(data),
            "raw": {
                "source_content_sha256": "a" * 64,
                "raw_snapshot_sha256": "d" * 64,
            },
            "profile": {
                "profile_file_sha256": "e" * 64,
                "evidence_file_sha256": "f" * 64,
                "profile_sha256": "0" * 64,
                "evidence_ledger_sha256": "3" * 64,
                "profile_context_sha256": "2" * 64,
            },
            "extraction": {
                "output": extraction,
                "receipt": self._receipt("semantic_vacancy_extraction", extraction),
            },
            "alignment": {
                "output": alignment,
                "receipt": self._receipt("evidence_alignment", alignment),
            },
            "scoring": {
                "parameters_sha256": processing_module.ScoringParams().parameters_hash,
                "opportunity_policy_sha256": processing_module.OPPORTUNITY_POLICY_SHA256,
                "expected_score": self._expected_score(),
            },
        }

    def _database_bindings(self, data: pathlib.Path) -> dict:
        def identity(path: str, ino: int) -> dict:
            return {
                "path": path,
                "dev": 111,
                "ino": ino,
                "uid": os.getuid(),
                "mode": 0o600,
                "nlink": 1,
            }

        return {
            "assessments": identity(str(data / "state" / "assessments.sqlite3"), 222),
            "vacancy": identity(str(data / "state" / "vacancies.sqlite3"), 333),
        }

    def _canonical_bytes(self, payload: dict) -> bytes:
        return processing_module.canonical_json(payload).encode("utf-8") + b"\n"

    def _write_envelope(self, data: pathlib.Path, raw_bytes: bytes, *, name: str | None = None) -> str:
        leaf_name = name or (hashlib.sha256(raw_bytes).hexdigest() + ".json")
        target = data / "state" / "processing-inbox" / leaf_name
        target.write_bytes(raw_bytes)
        os.chmod(target, 0o600)
        return leaf_name

    def _load_authority(self, data: pathlib.Path, name: str):
        return processing_module.load_envelope_authority(data, name)

    def _compose(self, data: pathlib.Path, payload: dict, *, file_sha: str | None = None):
        # Recompute the canonical file hash lazily so payloads that are
        # invalid as JSON numbers (NaN/Infinity/absurd ints) reach their
        # intended field validator instead of dying in a premature
        # canonicalization; such payloads refuse long before the final
        # file-hash proof.
        if file_sha is None:
            try:
                file_sha = hashlib.sha256(self._canonical_bytes(payload)).hexdigest()
            except (TypeError, ValueError):
                file_sha = "0" * 64
        return processing_module.compose_envelope_facts(
            payload,
            envelope_file_sha256=file_sha,
            expected_assessments_path=str(data / "state" / "assessments.sqlite3"),
            expected_vacancy_path=str(data / "state" / "vacancies.sqlite3"),
        )

    def _mutate(self, base: dict, path: tuple, value=DELETE):
        clone = copy.deepcopy(base)
        node = clone
        for key in path[:-1]:
            node = node[key]
        if value is self.DELETE:
            del node[path[-1]]
        else:
            node[path[-1]] = value
        return clone

    def _assert_compose_rejects(
        self, base: dict, data: pathlib.Path, path: tuple, value=DELETE, *, fragment: str
    ) -> None:
        mutated = self._mutate(base, path, value)
        with self.assertRaisesRegex(ValueError, fragment):
            self._compose(data, mutated)

    def _assert_output_rejects(
        self,
        base: dict,
        data: pathlib.Path,
        section: str,
        path: tuple,
        value,
        *,
        fragment: str,
    ) -> None:
        """Mutate one LLM output field, re-bind the receipt, expect refusal."""

        mutated = self._mutate(base, (section, "output") + tuple(path), value)
        output = mutated[section]["output"]
        task = (
            "semantic_vacancy_extraction"
            if section == "extraction"
            else "evidence_alignment"
        )
        mutated[section]["receipt"] = self._receipt(task, output)
        with self.assertRaisesRegex(ValueError, fragment):
            self._compose(data, mutated)

    # ------------------------------------------------------------ positive

    def test_golden_envelope_binds_linked_immutable_facts(self) -> None:
        data = self._tree()
        payload = self._golden_payload(data)
        canonical = self._canonical_bytes(payload)
        name = self._write_envelope(data, canonical)

        baseline = _fd_count()
        descriptors, loaded, file_sha, semantic_sha = self._load_authority(data, name)
        try:
            facts = self._compose(data, loaded, file_sha=file_sha)
        finally:
            descriptors.close()
        self.assertEqual(baseline, _fd_count())

        self.assertEqual(file_sha, name[:64])
        self.assertEqual(semantic_sha, hashlib.sha256(canonical[:-1]).hexdigest())
        self.assertEqual(facts.envelope_file_sha256, file_sha)
        self.assertEqual(facts.envelope_semantic_sha256, semantic_sha)
        self.assertEqual(facts.envelope_semantic_bytes, canonical[:-1])
        self.assertEqual(facts.operation_id, "op-12345678")
        self.assertEqual(facts.job_key, self.JOB_KEY)
        self.assertEqual(facts.profile_id, self.PROFILE_ID)
        self.assertEqual(facts.track, "backend")
        self.assertEqual(facts.config_closure_files, (("/cfg/product.toml", "b" * 64),))
        self.assertEqual(facts.assessments.ino, 222)
        self.assertEqual(facts.vacancy.ino, 333)
        self.assertEqual(facts.raw.source_content_sha256, "a" * 64)
        self.assertEqual(len(facts.profile_binding_shas), 5)
        self.assertIsInstance(
            facts.extraction.output_structural, tuple
        )
        self.assertIsInstance(facts.extraction.receipt, processing_module.LLMReceipt)
        alignment_matches = dict(facts.alignment.output_structural)["matches"]
        self.assertIsInstance(alignment_matches[0], tuple)
        self.assertIn(
            ("requirement", "Own services end to end"), alignment_matches[0]
        )
        self.assertEqual(
            hashlib.sha256(facts.extraction.output_canonical).hexdigest(),
            facts.extraction.receipt.output_sha256,
        )
        self.assertEqual(facts.expected_score.fit, 0.42)
        processing_module._assert_fully_immutable(facts, "facts")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            facts.operation_id = "other"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            facts.config_closure_files[0][1] = "tampered"  # type: ignore[index]
        # Mutating the caller's source payload after compose cannot alter
        # already-constructed facts.
        payload["track"] = "mutated-after-compose"
        payload["extraction"]["output"]["title"] = "mutated-after-compose"
        self.assertEqual(facts.track, "backend")
        self.assertEqual(
            dict(facts.extraction.output_structural)["title"],
            "Senior Backend Engineer",
        )

    # ------------------------------------------------- authority-level gates

    def test_filename_and_path_aliases_refuse_exactly(self) -> None:
        data = self._tree()
        payload = self._golden_payload(data)
        good = self._write_envelope(data, self._canonical_bytes(payload))
        stem = good[:64]
        aliases = [
            "/" + good,
            "../" + good,
            "./" + good,
            "sub/" + good,
            stem.upper() + ".json",
            stem[:63] + ".json",
            stem + "aa.json",
            stem + ".txt",
            stem + ".JSON",
            "",
            ".",
            "..",
            good + "/",
            "with space.json",
            stem + ".json ",
            stem + "\n.json",
            "//" + good,
        ]
        baseline = _fd_count()
        for alias in aliases:
            with self.subTest(alias=alias[:40]):
                refused = None
                try:
                    processing_module.validate_envelope_name(alias)
                except Exception as exc:
                    refused = exc
                self.assertIsNotNone(refused, f"alias accepted: {alias!r}")
        del payload
        self.assertEqual(baseline, _fd_count())

    def test_canonical_bytes_hash_binding_and_noncanonical_refuse(self) -> None:
        data = self._tree()
        payload = self._golden_payload(data)
        canonical = self._canonical_bytes(payload)

        # Positive: exact bytes under exact name load and compose.
        name = self._write_envelope(data, canonical)
        descriptors, loaded, file_sha, semantic_sha = self._load_authority(data, name)
        descriptors.close()
        self.assertEqual(file_sha, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(semantic_sha, hashlib.sha256(canonical[:-1]).hexdigest())

        wrong_name = hashlib.sha256(b"different").hexdigest() + ".json"
        self._write_envelope(data, canonical, name=wrong_name)
        with self.assertRaises(ValueError):
            self._load_authority(data, wrong_name)

        noncanonical = [
            ("no trailing LF", canonical[:-1]),
            ("double trailing LF", canonical + b"\n"),
            ("pretty printed", json.dumps(payload, indent=2).encode() + b"\n"),
            (
                "reordered keys",
                json.dumps(payload, sort_keys=False, ensure_ascii=False).encode() + b"\n",
            ),
            ("extra spaces", b"  " + canonical),
            ("trailing spaces", canonical.rstrip(b"\n") + b"  \n"),
            ("BOM prefix", b"\xef\xbb\xbf" + canonical),
            ("empty body", b""),
        ]
        for label, body in noncanonical:
            with self.subTest(label=label):
                bad_name = self._write_envelope(data, body)
                with self.assertRaises(ValueError):
                    self._load_authority(data, bad_name)

    def test_strict_parser_poisons_refuse_at_parse_stage(self) -> None:
        poisons = [
            ("duplicate keys", b'{"schema_version":"x","schema_version":"y"}\n'),
            ("NaN literal", b'{"a":NaN}\n'),
            ("Infinity literal", b'{"a":Infinity}\n'),
            ("minus Infinity literal", b'{"a":-Infinity}\n'),
            ("bare control string", b'{"a":"\x01"}\n'),
            ("trailing junk", b'{"a":1} junk\n'),
        ]
        for label, body in poisons:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    processing_module.strict_json_loads(body)
        data = self._tree()
        baseline = _fd_count()
        for label, body in poisons:
            with self.subTest(label="loader:" + label):
                bad_name = self._write_envelope(data, body)
                with self.assertRaises(ValueError):
                    self._load_authority(data, bad_name)
        self.assertEqual(baseline, _fd_count())

    # ------------------------------------------------------- schema matrices

    def test_top_level_unknown_missing_type_matrix(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        top_keys = list(processing_module.ENVELOPE_TOP_LEVEL_KEYS)
        for key in top_keys:
            self._assert_compose_rejects(
                base, data, (key,), fragment="key set mismatch"
            )
        with self.assertRaises(ValueError):
            self._compose(data, self._mutate(base, ("schema_version",), "other.v1"))
        type_mutations = [
            (("schema_version",), 7, "schema_version"),
            (("operation_id",), 7, "operation_id"),
            (("operation_id",), "short", "operation_id"),
            (("job_key",), {"board": "b", "job_id": "j"}, "job_key"),
            (("job_key",), "no-separator", "job_key"),
            (("job_key",), "b:j:x", "job_key"),
            (("profile_id",), "profile-alpha", "profile_id"),
            (("profile_id",), "prf_" + "A" * 32, "profile_id"),
            (("profile_version",), "", "profile_version"),
            (("track",), True, "track"),
        ]
        for path, value, fragment in type_mutations:
            self._assert_compose_rejects(
                base, data, path, value, fragment=fragment
            )
        unknown = copy.deepcopy(base)
        unknown["unknown_top"] = {}
        with self.assertRaises(ValueError):
            self._compose(data, unknown)

    def test_config_binding_mutation_matrix(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        matrix = [
            (("config", "source_path"), "cfg/rel.toml", "absolute normalized"),
            (("config", "source_path"), 7, "must be a string"),
            (("config", "source_file_sha256"), "b" * 63, "hex"),
            (("config", "closure_files"), [], "must be an object"),
            (("config", "closure_files"), {}, "1..64"),
            (("config", "closure_files", "/cfg/product.toml"), self.DELETE, "must hold 1..64 entries"),
            (("config", "closure_files", "/cfg/product.toml"), "c" * 64, "source_path exactly once"),
            (("config", "closure_sha256"), "d" * 64, "closure_sha256 does not bind"),
            (("config", "closure_sha256"), "short", "hex"),
            (("config", "semantic_sha256"), None, "hex"),
        ]
        for path, value, fragment in matrix:
            self._assert_compose_rejects(base, data, path, value, fragment=fragment)

    def test_database_binding_mutation_matrix(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        matrix = [
            (("databases", "assessments", "path"), str(data / "state" / "other.db"), "assessments.path"),
            (("databases", "vacancy", "path"), str(data / "state" / "other.db"), "vacancy.path"),
            (("databases", "assessments", "dev"), 112, "one filesystem device"),
            (("databases", "vacancy", "ino"), 222, "distinct inodes"),
            (("databases", "assessments", "uid"), os.getuid() + 1, "current UID"),
            (("databases", "assessments", "mode"), 0o644, "0600"),
            (("databases", "assessments", "nlink"), 2, "exactly 1"),
            (("databases", "assessments", "dev"), True, "dev"),
            (("databases", "assessments", "ino"), 0, "ino"),
            (("databases", "assessments", "path"), 7, "path"),
        ]
        for path, value, fragment in matrix:
            self._assert_compose_rejects(base, data, path, value, fragment=fragment)
        third = copy.deepcopy(base)
        third["databases"]["archive"] = third["databases"]["vacancy"]
        with self.assertRaises(ValueError):
            self._compose(data, third)

    def test_raw_profile_scoring_binding_matrices(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        for field in ("source_content_sha256", "raw_snapshot_sha256"):
            self._assert_compose_rejects(
                base, data, ("raw", field), "z" * 64, fragment="hex"
            )
        for field in (
            "profile_file_sha256",
            "evidence_file_sha256",
            "profile_sha256",
            "evidence_ledger_sha256",
            "profile_context_sha256",
        ):
            self._assert_compose_rejects(
                base, data, ("profile", field), "q" * 65, fragment="hex"
            )
        self._assert_compose_rejects(
            base,
            data,
            ("scoring", "parameters_sha256"),
            "9" * 63,
            fragment="hex",
        )
        self._assert_compose_rejects(
            base,
            data,
            ("scoring", "opportunity_policy_sha256"),
            "8" * 63,
            fragment="hex",
        )
        with self.assertRaises(ValueError):
            self._compose(
                data,
                self._mutate(base, ("scoring", "expected_score", "fit_status"), 7),
            )
        missing_status = self._mutate(
            base, ("scoring", "expected_score", "fit_status")
        )
        with self.assertRaises(ValueError):
            self._compose(data, missing_status)

    def test_extraction_output_mutation_matrix(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        matrix = [
            (("extraction", "output", "title"), "", "extraction.title"),
            (("extraction", "output", "title"), "a\x01b", "extraction.title"),
            (("extraction", "output", "company"), 7, "extraction.company"),
            (("extraction", "output", "location"), None, "extraction.location"),
            (("extraction", "output", "responsibilities"), ["x"] * 513, "at most 512"),
            (("extraction", "output", "responsibilities"), [""], "responsibilities\\[0\\]"),
            (("extraction", "output", "required_skills"), "Python", "array"),
            (("extraction", "output", "work_authorisation"), ["y" * 8193], "work_authorisation\\[0\\]"),
            (("extraction", "output", "contract_type"), "z" * 257, "extraction.contract_type"),
            (("extraction", "output", "seniority"), 3, "extraction.seniority"),
            (("extraction", "output", "remote_policy"), None, "extraction.remote_policy"),
            (("extraction", "output", "extraction_confidence"), 1.5, "extraction_confidence"),
            (("extraction", "output", "extraction_confidence"), True, "extraction_confidence"),
            (("extraction", "output", "unknown_fields"), ["u"] * 257, "at most 256"),
            (("extraction", "output", "unknown_fields"), [""], "unknown_fields\\[0\\]"),
            (("extraction", "output", "contract_version"), "market-aligner.llm.v2", "contract_version"),
            (("extraction", "output", "source_content_sha256"), "a" * 63, "hex"),
        ]
        for path, value, fragment in matrix:
            self._assert_output_rejects(
                base, data, "extraction", tuple(path[2:]), value, fragment=fragment
            )
        # Prose controls stay structural; blank owner prose composes at
        # reason 3 and is refused only at reason 9.
        mutated = self._mutate(
            base,
            ("extraction", "output", "description"),
            "tab\tok\nok\rok",
        )
        mutated["extraction"]["receipt"] = self._receipt(
            "semantic_vacancy_extraction", mutated["extraction"]["output"]
        )
        facts = self._compose(data, mutated)
        self.assertIn(
            "\t", dict(facts.extraction.output_structural)["description"]
        )

    def test_receipt_mutation_matrix_with_rfc3339_forms(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        receipt_fragments = [
            (("model",), "", "receipt.model"),
            (("prompt_version",), 7, "prompt_version"),
            (("input_sha256",), "1" * 63, "hex"),
            (("receipt_id",), "", "receipt_id"),
            (("contract_version",), "v0", "contract_version must be"),
            # Length bound fails before the lexical form.
            (("created_at",), "", "20..64 characters"),
            (("created_at",), "2026-08-25", "20..64 characters"),
            (("created_at",), "2026-08-25T00:00:00", "20..64 characters"),
            (("created_at",), "20260825T000000Z", "20..64 characters"),
            (("created_at",), "2026-08-25 00:00:00Z", "RFC3339 YYYY-MM-DDTHH"),
            # Offset bounds then calendar validity.
            (("created_at",), "2026-08-25T00:00:00+25:00", "out-of-range UTC offset"),
            (("created_at",), "2026-08-25T00:00:00+00:70", "out-of-range UTC offset"),
            (("created_at",), "2026-13-01T00:00:00Z", "parse as RFC3339"),
        ]
        for section in ("extraction", "alignment"):
            # Task authority moved to reasons 9/10: a structurally valid
            # swapped task composes at reason 3 and is recorded verbatim.
            other_task = (
                "evidence_alignment"
                if section == "extraction"
                else "semantic_vacancy_extraction"
            )
            swapped = self._mutate(base, (section, "receipt", "task"), other_task)
            facts = self._compose(data, swapped)
            self.assertEqual(
                getattr(facts, section).receipt.task, other_task
            )
            for path, value, fragment in receipt_fragments:
                self._assert_compose_rejects(
                    base,
                    data,
                    (section, "receipt") + path,
                    value,
                    fragment=fragment,
                )
        # RFC3339 positives: Z form and numeric offsets.
        for created_at in (
            "2026-08-25T00:00:00+02:00",
            "2026-08-25t00:00:00z",
            "2026-08-25T00:00:00.123456Z",
        ):
            mutated = self._mutate(
                base, ("extraction", "receipt", "created_at"), created_at
            )
            facts = self._compose(data, mutated)
            self.assertEqual(facts.extraction.receipt.created_at, created_at)

    def test_alignment_output_mutation_matrix(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        matrix = [
            (("alignment", "output", "profile_id"), "profile-alpha", "profile_id"),
            (("alignment", "output", "matches"), {}, "array of at most 512"),
            (("alignment", "output", "matches", 0, "requirement"), "a\x02", "requirement"),
            (("alignment", "output", "matches", 0, "requirement"), "", "requirement"),
            (("alignment", "output", "matches", 0, "evidence_ids"), ["ev-1", "ev-1"], "unique evidence ids"),
            (("alignment", "output", "matches", 0, "evidence_ids"), ["e" * 257], "1..256 code points"),
            (("alignment", "output", "matches", 0, "evidence_ids"), ["z"] * 257, "at most 256"),
            (("alignment", "output", "matches", 0, "strength"), -0.1, "strength"),
            (("alignment", "output", "matches", 0, "unknown"), 1, "key set mismatch"),
            (("alignment", "output", "missing_requirements"), ["m"] * 513, "at most 512"),
            (("alignment", "output", "missing_requirements"), [None], "missing_requirements\\[0\\]"),
            (("alignment", "output", "technical_alignment"), 1.0001, "technical_alignment"),
            (("alignment", "output", "evidence_match"), -1, "evidence_match"),
            (("alignment", "output", "confidence"), True, "confidence"),
            (("alignment", "output", "unknowns"), [""], "unknowns\\[0\\]"),
            (("alignment", "output", "contract_version"), None, "contract_version must be"),
        ]
        for path, value, fragment in matrix:
            self._assert_output_rejects(
                base, data, "alignment", tuple(path[2:]), value, fragment=fragment
            )

    def test_expected_score_shape_and_cross_bindings(self) -> None:
        data = self._tree()
        base = self._golden_payload(data)
        matrix = [
            (("scoring", "expected_score", "fit"), 42.0, "score.fit"),
            (("scoring", "expected_score", "fit"), True, "score.fit"),
            (("scoring", "expected_score", "opportunity"), -0.5, "score.opportunity"),
            (("scoring", "expected_score", "final"), 150.0, "in \\[0,100\\]"),
            (("scoring", "expected_score", "final"), float("inf"), "finite number"),
            (("scoring", "expected_score", "final"), float("nan"), "finite number"),
            (("scoring", "expected_score", "fit_subscores", "interest"), True, "score.fit_subscores.interest"),
            (("scoring", "expected_score", "fit_subscores", "unknown_axis"), 0.5, "key set mismatch"),
            (("scoring", "expected_score", "opportunity_subscores", "accessibility"), 10.0, "accessibility"),
            # Structural format authority stays at reason 3; identity and
            # parameter/policy/score semantics moved to reasons 11-13.
            (("scoring", "expected_score", "profile_id"), "profile-alpha", "profile_id"),
        ]
        for path, value, fragment in matrix:
            self._assert_compose_rejects(base, data, tuple(path), value, fragment=fragment)
        # Identity relations now compose at reason 3.
        relaxed = self._mutate(
            base,
            ("scoring", "expected_score", "track"),
            "frontend",
        )
        facts = self._compose(data, relaxed)
        self.assertEqual(facts.expected_score.track, "frontend")

    def test_rfc3339_validator_positives_and_negatives(self) -> None:
        positives = [
            "2026-08-25T00:00:00Z",
            "2026-08-25t12:34:56z",
            "2026-08-25T00:00:00+05:30",
            "2026-08-25T00:00:00.999999-08:00",
        ]
        negatives = [
            "2026-08-25 00:00:00Z",
            "20260825T000000Z",
            "2026-08-25",
            "2026-08-25T00:00:00",
            "2026-08-25T00:00:00+24:01",
            "2026-08-25T00:00:00+00:70",
            "26-08-25T00:00:00Z",
            "2026-08-25T00:00Z",
            "2026-08-25T00:00:00.Z",
            "2026-08-25T00:60:00Z",
        ]
        for positive in positives:
            with self.subTest(value=positive):
                self.assertEqual(
                    processing_module.rfc3339_value(positive, "probe"), positive
                )
        for negative in negatives:
            with self.subTest(value=negative):
                with self.assertRaises(ValueError):
                    processing_module.rfc3339_value(negative, "probe")

    def test_semantic_posting_shape_exact_section_nine_mirror(self) -> None:
        golden = {
            "job_key": "boards.example:j-1",
            "board": "boards.example",
            "job_id": "j-1",
            "url": "https://boards.example/j/1",
            "posted_at": "2026-08-20T00:00:00Z",
            "fetched_at": "2026-08-25T00:00:00Z",
            "raw_text": "<html>body</html>",
            "raw_json": {"offers": [{"id": "1", "title": "Role"}]},
            "fetch_status": "fetched",
        }
        validated = processing_module.validate_semantic_posting_shape(golden)
        self.assertEqual(validated["job_key"], self.JOB_KEY)

        deep: dict = {"leaf": True}
        for _ in range(70):
            deep = {"a": deep}
        too_many_nodes = {str(index): 0 for index in range(100_001)}
        matrix = [
            (("url",), "https://x/" + "p" * 4090, "posting.url"),
            (("posted_at",), "not-a-time", "posted_at"),
            (("posted_at",), 5, "posted_at"),
            (("fetched_at",), None, None),
            (("fetched_at",), "2026-08-25 00:00:00Z", "fetched_at"),
            (("raw_text",), 5, "raw_text"),
            (("raw_text",), "x" * 4_000_001, "raw_text"),
            (("raw_text",), "ok\x01text", "raw_text"),
            (("raw_json",), [1, 2], "parsed JSON object or null"),
            (("raw_json",), '{"a":1}', "parsed JSON object or null"),
            (("raw_json",), {"bad\x01key": 1}, "object keys must be strings"),
            (("raw_json",), {"nested": {"ctrl": "v\x02"}}, "posting.raw_json.nested.ctrl"),
            (("raw_json",), {"list": ["ok", "bad\x03"]}, "raw_json.list[1]"),
            (("raw_json",), deep, "depth"),
            (("raw_json",), too_many_nodes, "nodes"),
            (("fetch_status",), "pending", 'exactly "fetched"'),
            (("fetch_status",), None, None),
            (("board",), "b" * 129, "posting.board"),
            (("job_id",), "j" * 300, "posting.job_id"),
            (("job_key",), "badformat", "job_key"),
            (("extra",), 1, "exact keys"),
        ]
        for path, value, fragment in matrix:
            with self.subTest(path=path, value=str(value)[:20]):
                mutated = copy.deepcopy(golden)
                node = mutated
                for key in path[:-1]:
                    node = node[key]
                if fragment is None and value is None:
                    del node[path[-1]]
                    with self.assertRaises(ValueError):
                        processing_module.validate_semantic_posting_shape(mutated)
                    continue
                node[path[-1]] = value
                with self.assertRaises(ValueError):
                    processing_module.validate_semantic_posting_shape(mutated)
        # Null-tolerant fields accept explicit nulls.
        nullable = copy.deepcopy(golden)
        nullable["posted_at"] = None
        nullable["raw_text"] = None
        nullable["raw_json"] = None
        processing_module.validate_semantic_posting_shape(nullable)
        # Nested JSON objects with clean strings pass control traversal.
        rich = copy.deepcopy(golden)
        rich["raw_json"] = {
            "meta": {"tags": ["a", "b"], "count": 2, "flag": False, "none": None}
        }
        processing_module.validate_semantic_posting_shape(rich)

    # ------------------------------------------------ descriptor-level gates

    def test_descriptor_mode_link_symlink_growth_swap_refuse(self) -> None:
        data = self._tree()
        payload = self._golden_payload(data)
        canonical = self._canonical_bytes(payload)
        inbox = data / "state" / "processing-inbox"
        target = inbox / (hashlib.sha256(canonical).hexdigest() + ".json")
        target.write_bytes(canonical)
        os.chmod(target, 0o600)
        baseline = _fd_count()

        witness = inbox / "witness.bin"
        witness.write_bytes(b"x")
        link_base = inbox / "link-base.json"
        link_base.write_bytes(canonical)
        os.chmod(link_base, 0o600)
        os.link(link_base, inbox / "hardlinked-name.json")
        descriptors = processing_module._DescriptorSet()
        try:
            _root, _state, level = processing_module.open_processing_authority(
                data, descriptors
            )
            with self.assertRaises(ValueError):  # nlink==2 on the linked pair
                processing_module._RetainedLeaf(
                    level, "hardlinked-name.json", maximum=processing_module.MAX_ENVELOPE_BYTES
                )
            symlinked = inbox / "symlinked.json"
            symlinked.symlink_to(target.name)
            with self.assertRaises(ValueError):  # private-regular leaf lstat
                processing_module._RetainedLeaf(
                    level, "symlinked.json", maximum=processing_module.MAX_ENVELOPE_BYTES
                )
            leaf = processing_module._RetainedLeaf(
                level, target.name, maximum=processing_module.MAX_ENVELOPE_BYTES
            )
            descriptors.push_leaf(leaf)
            self.assertEqual(canonical, leaf.data)

            os.chmod(target, 0o644)
            with self.assertRaises(ValueError):
                leaf.revalidate(level)
            os.chmod(target, 0o600)
            leaf.revalidate(level)

            with open(target, "ab") as handle:
                handle.write(b"\n")
            with self.assertRaises(ValueError):
                leaf.revalidate(level)
            with open(target, "wb") as handle:
                handle.write(canonical)
            leaf.revalidate(level)

            replacement = pathlib.Path(self.root) / "replacement.json"
            replacement.write_bytes(canonical)
            os.chmod(replacement, 0o600)
            os.replace(replacement, target)
            with self.assertRaises(ValueError):  # inode swap
                leaf.revalidate(level)
        finally:
            descriptors.close()
            os.unlink(inbox / "hardlinked-name.json")
            link_base.unlink()
            symlinked.unlink(missing_ok=True)
            witness.unlink()
        self.assertEqual(baseline, _fd_count())

    def test_valid_payload_with_wrong_file_sha_refuses_exactly(self) -> None:
        data = self._tree()
        payload = self._golden_payload(data)
        wrong_sha = hashlib.sha256(b"unrelated bytes").hexdigest()
        with self.assertRaisesRegex(
            ValueError,
            "SHA-256 of the exact canonical envelope bytes plus one LF",
        ):
            self._compose(data, payload, file_sha=wrong_sha)
        # The exact correct hash still composes.
        facts = self._compose(data, payload)
        self.assertEqual(len(facts.operation_id), len("op-12345678"))

    def test_nonfinite_values_refuse_at_intended_stages(self) -> None:
        golden = {
            "job_key": "boards.example:j-1",
            "board": "boards.example",
            "job_id": "j-1",
            "url": "https://boards.example/j/1",
            "posted_at": None,
            "fetched_at": "2026-08-25T00:00:00Z",
            "raw_text": None,
            "raw_json": {"offers": [{"price": float("nan")}]},
            "fetch_status": "fetched",
        }
        with self.assertRaisesRegex(ValueError, "must be a finite JSON number"):
            processing_module.validate_semantic_posting_shape(golden)
        mutated = copy.deepcopy(golden)
        mutated["raw_json"] = {"flag": float("infinity")}
        with self.assertRaisesRegex(ValueError, "must be a finite JSON number"):
            processing_module.validate_semantic_posting_shape(mutated)

    def test_no_write_mtime_fd_baseline_across_success_and_rejections(self) -> None:
        data = self._tree()

        def snapshot():
            state = []
            for path in sorted(data.rglob("*")):
                info = path.lstat()
                state.append(
                    (
                        str(path),
                        path.name,
                        info.st_mtime_ns,
                        info.st_size,
                        info.st_mode,
                        path.read_bytes() if path.is_file() else b"",
                    )
                )
            return state

        payload = self._golden_payload(data)
        canonical = self._canonical_bytes(payload)

        # Pre-create EVERY fixture leaf before the snapshot; afterwards only
        # read/refusal operations run.
        good_name = self._write_envelope(data, canonical)
        no_lf_name = self._write_envelope(data, canonical[:-1])
        poison_name = self._write_envelope(data, b'{"a":NaN}\n')
        schema_mutated = self._mutate(
            payload, ("extraction", "output", "title"), ""
        )
        schema_mutated["extraction"]["receipt"] = self._receipt(
            "semantic_vacancy_extraction", schema_mutated["extraction"]["output"]
        )
        bad_schema_name = self._write_envelope(
            data, self._canonical_bytes(schema_mutated)
        )

        before = snapshot()
        fd_baseline = _fd_count()

        descriptors, loaded, file_sha, semantic_sha = self._load_authority(
            data, good_name
        )
        try:
            facts = self._compose(data, loaded, file_sha=file_sha)
            self.assertEqual(semantic_sha, facts.envelope_semantic_sha256)
        finally:
            descriptors.close()
        self.assertIsNotNone(facts.operation_id)

        # Missing leaf: exact contracted filename refusal.
        with self.assertRaises(processing_module.ProcessingRefused) as refused:
            self._load_authority(data, "missing-envelope.json")
        self.assertEqual(
            refused.exception.reason,
            processing_module.REASON_ENVELOPE_PATH,
        )

        # Alias spellings: same exact filename refusal class and reason.
        for alias in ("../escape.json", "/tmp/escape.json"):
            with self.assertRaises(processing_module.ProcessingRefused) as refused:
                self._load_authority(data, alias)
            self.assertEqual(
                refused.exception.reason,
                processing_module.REASON_ENVELOPE_PATH,
            )

        # Byte-level poisons refuse at the strict parse stage.
        for name in (no_lf_name,):
            with self.assertRaises(ValueError):
                self._load_authority(data, name)
        with self.assertRaisesRegex(ValueError, "invalid JSON document|nonfinite"):
            self._load_authority(data, poison_name)

        # Schema-invalid but well-formed envelope: nested field stage.
        descriptors, loaded, file_sha, _semantic = self._load_authority(
            data, bad_schema_name
        )
        try:
            with self.assertRaisesRegex(ValueError, "extraction.title"):
                self._compose(data, loaded, file_sha=file_sha)
        finally:
            descriptors.close()

        campaign_baseline = _fd_count()
        for _ in range(50):
            with self.assertRaises(processing_module.ProcessingRefused) as refused:
                self._load_authority(data, "missing-envelope.json")
            self.assertEqual(
                refused.exception.reason,
                processing_module.REASON_ENVELOPE_PATH,
            )
        self.assertEqual(campaign_baseline, _fd_count())
        self.assertEqual(fd_baseline, _fd_count())
        self.assertEqual(before, snapshot())


import contextlib
import sqlite3

from market_aligner.state.migrations import (
    FIT001_PROCESSING_RECEIPTS,
    FIT001_RECEIPTS_DDL,
    LEDGER_DDL,
)


class StageDPart3AReplayTests(TempRootTestCase):
    """Part 3A provider-free read-only replay through production seams."""

    GOLDEN = StageDEnvelopeAuthorityTests(
        "test_golden_envelope_binds_linked_immutable_facts"
    )
    RECEIPT_T = "2026-08-25T12:00:00.000000Z"

    # ------------------------------------------------------------------
    # World fixtures (manual sqlite only; no side-effecting constructors)
    # ------------------------------------------------------------------

    def _new_world(self) -> dict:
        base = (
            pathlib.Path(self.root) / f"world{len(self._worlds)}"
        ).resolve()
        self._worlds.append(base)
        cfg_dir = base / "cfg"
        data = (base / "data").resolve()
        cfg_dir.mkdir(parents=True)
        data.mkdir()
        os.chmod(cfg_dir, 0o755)
        os.chmod(data, 0o700)
        (data / "state" / "processing-inbox").mkdir(parents=True)
        os.chmod(data / "state", 0o700)
        os.chmod(data / "state" / "processing-inbox", 0o700)
        cfg_path = cfg_dir / "product.toml"
        cfg_path.write_text(
            "boards:\n  enabled:\n    - board\n", encoding="utf-8"
        )
        os.chmod(cfg_path, 0o600)
        return {
            "base": base,
            "cfg_dir": cfg_dir,
            "cfg": str(cfg_path),
            "data": data,
        }

    def setUp(self) -> None:
        super().setUp()
        self._worlds: list[pathlib.Path] = []

    def _databases(self, world: dict, *, canonical_store: bool) -> tuple[pathlib.Path, pathlib.Path]:
        data = world["data"]
        main_db = data / "state" / "assessments.sqlite3"
        vac_db = data / "state" / "vacancies.sqlite3"
        conn = sqlite3.connect(main_db)
        if canonical_store:
            conn.execute(LEDGER_DDL)
            conn.execute(FIT001_RECEIPTS_DDL)
            conn.execute(
                "INSERT INTO market_aligner_schema_migrations(version,name,checksum)"
                " VALUES(?,?,?)",
                (
                    FIT001_PROCESSING_RECEIPTS.version,
                    FIT001_PROCESSING_RECEIPTS.name,
                    FIT001_PROCESSING_RECEIPTS.checksum,
                ),
            )
            conn.commit()
        vconn = sqlite3.connect(vac_db)
        vconn.close()
        conn.close()
        os.chmod(main_db, 0o600)
        os.chmod(vac_db, 0o600)
        return main_db, vac_db

    def _identity_node(self, path: pathlib.Path) -> dict:
        info = os.stat(path)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        return {
            "path": str(path),
            "dev": info.st_dev,
            "ino": info.st_ino,
            "uid": info.st_uid,
            "mode": 0o600,
            "nlink": info.st_nlink,
        }

    def _payload(self, world: dict, main_db: pathlib.Path, vac_db: pathlib.Path,
                 *, track: str = "backend") -> dict:
        from market_aligner.config_loader import snapshot_config

        merged, identities = snapshot_config(world["cfg"])
        closure = dict(identities)
        payload = self.GOLDEN._golden_payload(world["data"])
        payload["track"] = track
        payload["config"] = {
            "source_path": str(world["cfg"]),
            "source_file_sha256": closure[str(world["cfg"])],
            "closure_files": closure,
            "closure_sha256": hashlib.sha256(
                processing_module.canonical_json(closure).encode("utf-8")
            ).hexdigest(),
            "semantic_sha256": hashlib.sha256(
                processing_module.canonical_json(merged).encode("utf-8")
            ).hexdigest(),
        }
        payload["databases"] = {
            "assessments": self._identity_node(main_db),
            "vacancy": self._identity_node(vac_db),
        }
        return payload

    def _canonical_bytes(self, payload: dict) -> bytes:
        return processing_module.canonical_json(payload).encode("utf-8") + b"\n"

    def _stage(self, world: dict, payload: dict) -> str:
        raw_bytes = self._canonical_bytes(payload)
        name = hashlib.sha256(raw_bytes).hexdigest() + ".json"
        target = world["data"] / "state" / "processing-inbox" / name
        target.write_bytes(raw_bytes)
        os.chmod(target, 0o600)
        return name

    def _facts(self, world: dict, payload: dict):
        return processing_module.compose_envelope_facts(
            payload,
            envelope_file_sha256=hashlib.sha256(self._canonical_bytes(payload)).hexdigest(),
            expected_assessments_path=str(world["data"] / "state" / "assessments.sqlite3"),
            expected_vacancy_path=str(world["data"] / "state" / "vacancies.sqlite3"),
        )

    def _build_receipt(self, payload: dict, facts, binding_sha: str) -> tuple[dict, bytes]:
        pm = processing_module
        receipt = {
            "schema_version": pm.RECEIPT_SCHEMA,
            "operation_id": payload["operation_id"],
            "job_key": payload["job_key"],
            "profile_id": payload["profile_id"],
            "profile_version": payload["profile_version"],
            "track": payload["track"],
            "binding_sha256": binding_sha,
            "envelope_file_sha256": facts.envelope_file_sha256,
            "envelope_semantic_sha256": facts.envelope_semantic_sha256,
            "config": copy.deepcopy(payload["config"]),
            "databases": copy.deepcopy(payload["databases"]),
            "raw": copy.deepcopy(payload["raw"]),
            "profile": copy.deepcopy(payload["profile"]),
            "extraction": copy.deepcopy(payload["extraction"]),
            "alignment": copy.deepcopy(payload["alignment"]),
            "scoring": copy.deepcopy(payload["scoring"]),
            "normalised_projection": {
                "job_key": payload["job_key"],
                "normalized_json_sha256": hashlib.sha256(b"{}").hexdigest(),
                "normalized_at": self.RECEIPT_T,
            },
            "assessment_projection": {
                "profile_id": payload["profile_id"],
                "job_key": payload["job_key"],
                "score_payload_hash": hashlib.sha256(b"score").hexdigest(),
                "state": "scored",
                "created_at": self.RECEIPT_T,
                "updated_at": self.RECEIPT_T,
            },
        }
        for flag in pm._RECEIPT_FALSE_FLAGS:
            receipt[flag] = False
        receipt["assessment_event"] = {
            "id": 1,
            "event_type": pm.EVENT_TYPE_PROCESSING_SCORE_ACCEPTED,
            "actor_kind": "deterministic",
            "payload_sha256": "",
            "created_at": self.RECEIPT_T,
        }
        event_payload = pm.build_processing_event_payload(receipt)
        payload_sha = hashlib.sha256(
            pm.canonical_json(event_payload).encode("utf-8")
        ).hexdigest()
        receipt["assessment_event"]["payload_sha256"] = payload_sha
        receipt["assessment_event"]["idempotency_key"] = pm.expected_idempotency_key(
            payload["profile_id"], payload["job_key"], payload_sha
        )
        receipt["created_at"] = self.RECEIPT_T
        receipt["self_hash"] = pm.receipt_self_hash(
            {k: v for k, v in receipt.items() if k != "self_hash"}
        )
        return receipt, pm.sealed_receipt_bytes(receipt)

    def _seed_exact(self, world: dict, payload: dict, *, track_override: str | None = None) -> bytes:
        """Stage envelope + seed one exact self-validating receipt row."""
        pm = processing_module
        if track_override is not None:
            payload["track"] = track_override
        name = self._stage(world, payload)
        facts = self._facts(world, payload)
        _binding, binding_sha = pm.build_processing_binding_from_facts(facts)
        receipt, sealed = self._build_receipt(payload, facts, binding_sha)
        conn = sqlite3.connect(world["data"] / "state" / "assessments.sqlite3")
        conn.execute(
            "INSERT INTO processing_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt["operation_id"],
                receipt["profile_id"],
                receipt["job_key"],
                receipt["track"],
                binding_sha,
                facts.envelope_file_sha256,
                facts.envelope_semantic_sha256,
                receipt["normalised_projection"]["normalized_json_sha256"],
                receipt["assessment_projection"]["score_payload_hash"],
                1,
                receipt["self_hash"],
                hashlib.sha256(sealed).hexdigest(),
                sealed,
                receipt["created_at"],
            ),
        )
        conn.commit()
        conn.close()
        payload["_staged_name"] = name
        return sealed

    def _cli(self, payload: dict, *, operation_id: str | None = None,
             config_path: str | None = None, profile_id: str | None = None,
             job_key: str | None = None, track: str | None = None) -> dict:
        config = payload.get("config") or {}
        return {
            "supplied_operation_id": (
                payload.get("operation_id", "op-12345678")
                if operation_id is None
                else operation_id
            ),
            "supplied_config_path": (
                config.get("source_path", "/tmp/cfg/product.toml")
                if config_path is None
                else config_path
            ),
            "supplied_profile_id": (
                payload.get("profile_id", "prf_" + "a" * 32)
                if profile_id is None
                else profile_id
            ),
            "supplied_job_key": (
                payload.get("job_key", "board:job-1") if job_key is None else job_key
            ),
            "supplied_track": (
                payload.get("track", "backend") if track is None else track
            ),
        }

    def _replay(self, world: dict, name: str, payload: dict, **overrides):
        return processing_module.run_read_only_replay(
            world["data"], name, **{**self._cli(payload), **overrides}
        )

    def _tree(self, root: pathlib.Path) -> list[str]:
        return sorted(str(p.relative_to(root)) for p in root.rglob("*"))

    def _refused(self, callable_, reason: str):
        with self.assertRaises(processing_module.ProcessingRefused) as refused:
            callable_()
        self.assertEqual(refused.exception.reason, reason)
        return refused.exception

    # ------------------------------------------------------------------
    # Objective cases F1-F8 plus chain/event/FD proofs
    # ------------------------------------------------------------------

    def test_exact_replay_of_sealed_receipt(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        sealed = self._seed_exact(world, payload)
        result = self._replay(world, payload["_staged_name"], payload)
        self.assertEqual(result.disposition, "exact_replay")
        self.assertEqual(result.stored_receipt_bytes, sealed)
        self.assertEqual(result.detail, "sealed replay")

    def test_self_validating_receipt_under_changed_staging_is_reason6(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        self._seed_exact(world, payload)
        changed = copy.deepcopy(payload)
        changed.pop("_staged_name", None)
        changed["scoring"]["expected_score"]["final"] = (
            float(changed["scoring"]["expected_score"]["final"]) + 0.25
        )
        changed_name = self._stage(world, changed)
        changed_facts = self._facts(world, changed)
        _changed_binding, changed_binding_sha = (
            pm.build_processing_binding_from_facts(changed_facts)
        )
        receipt2, sealed2 = self._build_receipt(
            changed, changed_facts, changed_binding_sha
        )

        conn = sqlite3.connect(main_db)
        try:
            conn.execute("DELETE FROM processing_receipts")
            conn.execute(
                "INSERT INTO processing_receipts"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    receipt2["operation_id"],
                    receipt2["profile_id"],
                    receipt2["job_key"],
                    receipt2["track"],
                    changed_binding_sha,
                    changed_facts.envelope_file_sha256,
                    changed_facts.envelope_semantic_sha256,
                    receipt2["normalised_projection"]["normalized_json_sha256"],
                    receipt2["assessment_projection"]["score_payload_hash"],
                    1,
                    receipt2["self_hash"],
                    hashlib.sha256(sealed2).hexdigest(),
                    sealed2,
                    receipt2["created_at"],
                ),
            )
            conn.commit()
        finally:
            conn.close()

        baseline = _fd_count()
        refused = self._refused(
            lambda: self._replay(world, payload["_staged_name"], payload),
            pm.REASON_EXISTING_RECEIPT,
        )
        self.assertTrue(refused.detail)
        self.assertEqual(_fd_count(), baseline)
        self.assertNotEqual(changed_name, payload["_staged_name"])
        self.assertTrue(sealed2)

    def test_event_payload_isolation_normalized_move_stays_provisional(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        sealed = self._seed_exact(world, payload)

        mutated = json.loads(sealed.decode("utf-8"))
        moved = hashlib.sha256(b"other-normalised-json").hexdigest()
        mutated["normalised_projection"]["normalized_json_sha256"] = moved
        mutated.pop("self_hash")
        mutated["self_hash"] = pm.receipt_self_hash(mutated)
        new_sealed = pm.sealed_receipt_bytes(mutated)
        old_event = json.loads(sealed.decode("utf-8"))["assessment_event"]
        new_event = json.loads(new_sealed.decode("utf-8"))["assessment_event"]
        self.assertEqual(new_event["idempotency_key"],
                         old_event["idempotency_key"])
        self.assertEqual(new_event["payload_sha256"],
                         old_event["payload_sha256"])

        conn = sqlite3.connect(main_db)
        try:
            conn.execute(
                "UPDATE processing_receipts SET normalized_sha256 = ?,"
                " receipt_self_hash = ?, receipt_file_sha256 = ?,"
                " receipt_bytes = ? WHERE operation_id = ?",
                (
                    moved,
                    mutated["self_hash"],
                    hashlib.sha256(new_sealed).hexdigest(),
                    new_sealed,
                    payload["operation_id"],
                ),
            )
            conn.commit()
        finally:
            conn.close()

        baseline = _fd_count()
        result = self._replay(world, payload["_staged_name"], payload)
        self.assertEqual(
            result.disposition,
            pm.DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY,
        )
        self.assertIsNone(result.stored_receipt_bytes)
        self.assertIn("payload_sha256", result.detail)
        self.assertIn("rebuilt payload", result.detail)
        self.assertEqual(_fd_count(), baseline)

    def test_wellformed_alternate_assessments_path_maps_reason5(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        alt = world["data"] / "state" / "journal.sqlite3"
        alt_conn = sqlite3.connect(alt)
        alt_conn.close()
        os.chmod(alt, 0o600)
        info = os.stat(alt)
        payload = self._payload(world, main_db, vac_db)
        payload["databases"]["assessments"] = {
            "path": str(alt),
            "dev": info.st_dev,
            "ino": info.st_ino,
            "uid": info.st_uid,
            "mode": 0o600,
            "nlink": info.st_nlink,
        }
        name = self._stage(world, payload)

        baseline = _fd_count()
        before = self._tree(world["base"])
        refused = self._refused(
            lambda: self._replay(world, name, payload),
            pm.REASON_CONFIG_DATABASE,
        )
        self.assertIn("canonical", refused.detail)
        self.assertEqual(self._tree(world["base"]), before)
        self.assertEqual(_fd_count(), baseline)

    def test_after_prestat_private_growth_is_reason3_fd_safe(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        name = self._stage(world, payload)
        target = (
            world["data"] / "state" / "processing-inbox" / name
        )

        def grow_envelope_leaf() -> None:
            with open(target, "ab") as handle:
                handle.write(b"x")

        pm.install_fault("after_envelope_prestat", grow_envelope_leaf)
        self.addCleanup(pm.clear_faults)

        baseline = _fd_count()
        before = self._tree(world["base"])
        refused = self._refused(
            lambda: self._replay(world, name, payload),
            pm.REASON_ENVELOPE_BYTES,
        )
        self.assertIn("between pre-stat and open", refused.detail)
        self.assertEqual(self._tree(world["base"]), before)
        self.assertEqual(_fd_count(), baseline)

    def test_absent_store_bootstrap_then_absent_operation(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        name = self._stage(world, payload)
        empty = self._replay(world, name, payload)
        self.assertEqual(empty.disposition, "definitive_absence")
        self.assertIsNone(empty.stored_receipt_bytes)
        self.assertIn("bootstrap eligible", empty.detail)
        conn = sqlite3.connect(main_db)
        conn.execute(LEDGER_DDL)
        conn.execute(FIT001_RECEIPTS_DDL)
        conn.execute(
            "INSERT INTO market_aligner_schema_migrations(version,name,checksum)"
            " VALUES(?,?,?)",
            (
                FIT001_PROCESSING_RECEIPTS.version,
                FIT001_PROCESSING_RECEIPTS.name,
                FIT001_PROCESSING_RECEIPTS.checksum,
            ),
        )
        conn.commit()
        conn.close()
        compatible_empty = self._replay(world, name, payload)
        self.assertEqual(compatible_empty.disposition, "definitive_absence")
        self.assertIn("no receipt", compatible_empty.detail)

    def test_partial_or_malformed_store_stays_provisional(self) -> None:
        pm = processing_module
        cases = (
            "table_without_ledger",
            "ledger_without_table",
            "wrong_checksum",
            "tampered_sealed_bytes",
            "stale_file_hash",
        )
        for case in cases:
            with self.subTest(case=case):
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                facts = self._facts(world, payload)
                name = self._stage(world, payload)
                _binding, binding_sha = pm.build_processing_binding_from_facts(facts)
                receipt, sealed = self._build_receipt(payload, facts, binding_sha)
                stored_sealed = sealed
                stored_file_hash = hashlib.sha256(sealed).hexdigest()
                conn = sqlite3.connect(main_db)
                if case == "table_without_ledger":
                    conn.execute(FIT001_RECEIPTS_DDL)
                elif case == "ledger_without_table":
                    conn.execute(LEDGER_DDL)
                    conn.execute(
                        "INSERT INTO market_aligner_schema_migrations"
                        "(version,name,checksum) VALUES(?,?,?)",
                        (
                            FIT001_PROCESSING_RECEIPTS.version,
                            FIT001_PROCESSING_RECEIPTS.name,
                            FIT001_PROCESSING_RECEIPTS.checksum,
                        ),
                    )
                elif case == "wrong_checksum":
                    conn.execute(LEDGER_DDL)
                    conn.execute(FIT001_RECEIPTS_DDL)
                    conn.execute(
                        "INSERT INTO market_aligner_schema_migrations"
                        "(version,name,checksum) VALUES(?,?,?)",
                        (
                            FIT001_PROCESSING_RECEIPTS.version,
                            FIT001_PROCESSING_RECEIPTS.name,
                            "f" * 64,
                        ),
                    )
                else:
                    conn.execute(LEDGER_DDL)
                    conn.execute(FIT001_RECEIPTS_DDL)
                    conn.execute(
                        "INSERT INTO market_aligner_schema_migrations"
                        "(version,name,checksum) VALUES(?,?,?)",
                        (
                            FIT001_PROCESSING_RECEIPTS.version,
                            FIT001_PROCESSING_RECEIPTS.name,
                            FIT001_PROCESSING_RECEIPTS.checksum,
                        ),
                    )
                    if case == "tampered_sealed_bytes":
                        mutable = bytearray(sealed)
                        mutable[-20] ^= 0x01
                        stored_sealed = bytes(mutable)
                    elif case == "stale_file_hash":
                        stored_file_hash = "f" * 64
                if case != "table_without_ledger" and case != "ledger_without_table":
                    conn.execute(
                        "INSERT INTO processing_receipts"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            receipt["operation_id"],
                            receipt["profile_id"],
                            receipt["job_key"],
                            receipt["track"],
                            binding_sha,
                            facts.envelope_file_sha256,
                            facts.envelope_semantic_sha256,
                            receipt["normalised_projection"]["normalized_json_sha256"],
                            receipt["assessment_projection"]["score_payload_hash"],
                            1,
                            receipt["self_hash"],
                            stored_file_hash,
                            stored_sealed,
                            receipt["created_at"],
                        ),
                    )
                conn.commit()
                conn.close()
                result = self._replay(world, name, payload)
                self.assertEqual(
                    result.disposition,
                    pm.DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY,
                )
                self.assertIsNone(result.stored_receipt_bytes)

    # ------------------------------------------------------------------
    # Precedence: reasons 1 > 2 > 3 > 5 across load stages (no-write)
    # ------------------------------------------------------------------

    def test_invalid_operation_id_beats_missing_home_and_unsafe_name(self) -> None:
        pm = processing_module
        world = self._new_world()
        shutil.rmtree(world["data"])
        self.assertFalse(world["data"].exists())
        before = self._tree(world["base"])
        self._refused(
            lambda: self._replay(
                world,
                "../escape.json",
                {"operation_id": "short"},
                supplied_operation_id="short",
            ),
            pm.REASON_OPERATION_ID,
        )
        self.assertEqual(self._tree(world["base"]), before)

    def test_unsafe_lexical_name_beats_missing_data_home(self) -> None:
        pm = processing_module
        world = self._new_world()
        shutil.rmtree(world["data"])
        before = self._tree(world["base"])
        payload = {"operation_id": "op-12345678"}
        self._refused(
            lambda: self._replay(world, "../escape.json", payload),
            pm.REASON_ENVELOPE_PATH,
        )
        self.assertEqual(self._tree(world["base"]), before)

    def test_unsafe_lexical_spelling_beats_oversize_leaf(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        huge = b"x" * (processing_module.MAX_ENVELOPE_BYTES + 1)
        huge_name = hashlib.sha256(huge).hexdigest() + ".json"
        target = world["data"] / "state" / "processing-inbox" / huge_name
        target.write_bytes(huge)
        os.chmod(target, 0o600)
        self._refused(
            lambda: self._replay(
                world, f"../state/processing-inbox/{huge_name}", payload
            ),
            pm.REASON_ENVELOPE_PATH,
        )

    def test_data_home_authority_refusals_are_reason5_nowrite(self) -> None:
        pm = processing_module
        variants = ("missing_data_home", "wrong_mode_state", "symlinked_inbox")
        for variant in variants:
            with self.subTest(variant=variant):
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                if variant == "missing_data_home":
                    shutil.rmtree(world["data"])
                elif variant == "wrong_mode_state":
                    os.chmod(world["data"] / "state", 0o755)
                else:
                    real = world["data"] / "state" / "processing-inbox-real"
                    os.rename(world["data"] / "state" / "processing-inbox", real)
                    os.symlink(real, world["data"] / "state" / "processing-inbox")
                before = self._tree(world["base"])
                self._refused(
                    lambda: self._replay(world, f"{hashlib.sha256(b'none').hexdigest()}.json", payload),
                    pm.REASON_CONFIG_DATABASE,
                )
                self.assertEqual(self._tree(world["base"]), before)

    def test_envelope_leaf_order_is_private_proof_before_size(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        inbox = world["data"] / "state" / "processing-inbox"
        huge = b"x" * (processing_module.MAX_ENVELOPE_BYTES + 1)
        huge_name = hashlib.sha256(huge).hexdigest() + ".json"

        missing_name = hashlib.sha256(b"absent").hexdigest() + ".json"
        self._refused(
            lambda: self._replay(world, missing_name, payload),
            pm.REASON_ENVELOPE_PATH,
        )

        staging = world["cfg_dir"] / "link-target.bin"
        staging.write_bytes(b"symlink body")
        os.chmod(staging, 0o600)
        os.symlink(staging, inbox / huge_name)
        self._refused(
            lambda: self._replay(world, huge_name, payload),
            pm.REASON_ENVELOPE_PATH,
        )
        os.unlink(inbox / huge_name)

        os.link(staging, inbox / huge_name)
        self._refused(
            lambda: self._replay(world, huge_name, payload),
            pm.REASON_ENVELOPE_PATH,
        )
        os.unlink(inbox / huge_name)

        target = inbox / huge_name
        target.write_bytes(huge)
        os.chmod(target, 0o644)
        self._refused(
            lambda: self._replay(world, huge_name, payload),
            pm.REASON_ENVELOPE_PATH,
        )

        os.chmod(target, 0o600)
        self._refused(
            lambda: self._replay(world, huge_name, payload),
            pm.REASON_ENVELOPE_BYTES,
        )

    def test_content_defects_after_safe_leaf_map_reason3(self) -> None:
        pm = processing_module
        for label, raw_bytes in (
            ("malformed_json", b"{ definitely not json"),
            ("noncanonical_tail", None),
        ):
            with self.subTest(case=label):
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                if raw_bytes is None:
                    raw_bytes = self._canonical_bytes(payload) + b"\n"
                name = hashlib.sha256(raw_bytes).hexdigest() + ".json"
                target = world["data"] / "state" / "processing-inbox" / name
                target.write_bytes(raw_bytes)
                os.chmod(target, 0o600)
                self._refused(
                    lambda: self._replay(world, name, payload),
                    pm.REASON_ENVELOPE_BYTES,
                )

    # ------------------------------------------------------------------
    # Read-only proof surface
    # ------------------------------------------------------------------

    def test_replay_never_touches_provider_or_material_seams(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        sealed = self._seed_exact(world, payload)

        explosions = []

        def exploding_open_existing(*_args, **_kwargs):
            explosions.append("ProfileStore.open_existing")
            raise AssertionError("ProfileStore.open_existing must not run during replay")

        def exploding_read_posting(*_args, **_kwargs):
            explosions.append("read_posting")
            raise AssertionError("read_posting must not run during replay")

        def exploding_accept_extraction(*_args, **_kwargs):
            explosions.append("accept_extraction")
            raise AssertionError("accept_extraction must not run during replay")

        def exploding_accept_alignment(*_args, **_kwargs):
            explosions.append("accept_alignment")
            raise AssertionError("accept_alignment must not run during replay")

        def exploding_score(*_args, **_kwargs):
            explosions.append("deterministic_score")
            raise AssertionError("deterministic_score must not run during replay")

        saved = (
            (pm.ProfileStore, "open_existing",
             pm.ProfileStore.__dict__["open_existing"]),
        )
        pm.ProfileStore.open_existing = staticmethod(exploding_open_existing)
        self.addCleanup(
            lambda: setattr(saved[0][0], "open_existing", saved[0][2])
        )
        for attribute, replacement in (
            ("read_posting", exploding_read_posting),
            ("accept_extraction", exploding_accept_extraction),
            ("accept_alignment", exploding_accept_alignment),
            ("deterministic_score", exploding_score),
        ):
            original = getattr(pm, attribute)
            setattr(pm, attribute, replacement)
            self.addCleanup(setattr, pm, attribute, original)

        result = self._replay(world, payload["_staged_name"], payload)
        self.assertEqual(result.disposition, "exact_replay")
        self.assertEqual(result.stored_receipt_bytes, sealed)
        self.assertEqual(explosions, [])

    def test_classification_statements_are_write_free_and_snapshots_stable(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        self._seed_exact(world, payload)

        allowed_pragmas = {
            "query_only",
            "database_list",
            "index_list",
            "index_info",
            "foreign_key_list",
        }
        denied: list[tuple[int, str]] = []

        def authorizer(action, arg1, _arg2, _database, _source):
            s = sqlite3
            if action in (
                s.SQLITE_SELECT,
                s.SQLITE_READ,
                s.SQLITE_FUNCTION,
                s.SQLITE_RECURSIVE,
            ):
                return s.SQLITE_OK
            if action == s.SQLITE_PRAGMA:
                if arg1 in allowed_pragmas:
                    return s.SQLITE_OK
                denied.append((action, str(arg1)))
                return s.SQLITE_DENY
            if action == s.SQLITE_ATTACH:
                return s.SQLITE_OK
            denied.append((action, str(arg1)))
            return s.SQLITE_DENY

        descriptors, staged_payload, file_sha, _semantic = pm.load_envelope_authority(
            world["data"], payload["_staged_name"]
        )
        try:
            facts = pm.compose_envelope_facts(
                staged_payload,
                envelope_file_sha256=file_sha,
                expected_assessments_path=str(main_db),
                expected_vacancy_path=str(vac_db),
            )
            admission = pm.admit_config_and_databases(world["data"], facts, descriptors)
            connection = pm._open_read_view(
                descriptors, admission["assessments"], admission["vacancy"]
            )
            try:
                connection.set_authorizer(authorizer)
                _binding, binding_sha = pm.build_processing_binding_from_facts(facts)
                classification = pm._classify_replay(
                    connection,
                    facts,
                    binding_sha,
                    descriptors,
                    admission["assessments"],
                    admission["vacancy"],
                )
            finally:
                connection.close()
            for leaf in list(descriptors.db_leaves):
                leaf.close(descriptors)
        finally:
            descriptors.close()
        self.assertEqual(classification.disposition, "exact_replay")
        self.assertEqual(denied, [])

        def logical_dump(path: pathlib.Path) -> str:
            ro = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                return "\n".join(ro.iterdump())
            finally:
                ro.close()

        before_main = logical_dump(main_db)
        before_vac = logical_dump(vac_db)
        result = self._replay(world, payload["_staged_name"], payload)
        self.assertEqual(result.disposition, "exact_replay")
        self.assertEqual(logical_dump(main_db), before_main)
        self.assertEqual(logical_dump(vac_db), before_vac)

    def test_full_chain_break_after_pin_fires_reason5_without_fd_leak(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        name = self._stage(world, payload)
        baseline = len(os.listdir("/dev/fd"))
        descriptors, staged_payload, file_sha, _semantic = pm.load_envelope_authority(
            world["data"], name
        )
        try:
            facts = pm.compose_envelope_facts(
                staged_payload,
                envelope_file_sha256=file_sha,
                expected_assessments_path=str(main_db),
                expected_vacancy_path=str(vac_db),
            )
            admission = pm.admit_config_and_databases(world["data"], facts, descriptors)
            old_state_ino = os.stat(world["data"] / "state").st_ino
            moved = world["data"] / "state-old"
            os.rename(world["data"] / "state", moved)
            (world["data"] / "state").mkdir()
            os.chmod(world["data"] / "state", 0o700)
            for child in moved.iterdir():
                os.rename(child, world["data"] / "state" / child.name)
            moved.rmdir()
            self.assertNotEqual(os.stat(world["data"] / "state").st_ino, old_state_ino)
            self._refused(
                lambda: pm._open_read_view(
                    descriptors, admission["assessments"], admission["vacancy"]
                ),
                pm.REASON_CONFIG_DATABASE,
            )
            for leaf in list(descriptors.db_leaves):
                leaf.close(descriptors)
        finally:
            descriptors.close()
        self.assertEqual(len(os.listdir("/dev/fd")), baseline)

    def test_event_payload_substitution_stays_provisional_not_reason6(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        facts = self._facts(world, payload)
        name = self._stage(world, payload)
        _binding, binding_sha = pm.build_processing_binding_from_facts(facts)
        receipt, _sealed = self._build_receipt(payload, facts, binding_sha)
        substituted = copy.deepcopy(receipt)
        substituted.pop("self_hash")
        substituted["track"] = "platform"
        substituted["self_hash"] = pm.receipt_self_hash(substituted)
        forged = pm.sealed_receipt_bytes(substituted)
        conn = sqlite3.connect(main_db)
        conn.execute(
            "INSERT INTO processing_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt["operation_id"],
                receipt["profile_id"],
                receipt["job_key"],
                receipt["track"],
                binding_sha,
                facts.envelope_file_sha256,
                facts.envelope_semantic_sha256,
                receipt["normalised_projection"]["normalized_json_sha256"],
                receipt["assessment_projection"]["score_payload_hash"],
                1,
                receipt["self_hash"],
                hashlib.sha256(forged).hexdigest(),
                forged,
                receipt["created_at"],
            ),
        )
        conn.commit()
        conn.close()
        result = self._replay(world, name, payload)
        self.assertEqual(
            result.disposition, pm.DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY
        )
        self.assertIsNone(result.stored_receipt_bytes)
        self.assertNotEqual(result.detail, "")

    def test_fd_baseline_fifty_mixed_outcomes(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        self._seed_exact(world, payload)
        name = payload["_staged_name"]
        baseline = len(os.listdir("/dev/fd"))
        for index in range(50):
            if index % 2 == 0:
                result = self._replay(world, name, payload)
                self.assertEqual(result.disposition, "exact_replay")
            else:
                os.rename(vac_db, vac_db.with_suffix(".hidden"))
                try:
                    self._refused(
                        lambda: self._replay(world, name, payload),
                        pm.REASON_CONFIG_DATABASE,
                    )
                finally:
                    os.rename(vac_db.with_suffix(".hidden"), vac_db)
        self.assertEqual(len(os.listdir("/dev/fd")), baseline)


class StageDPart3B1RawAdmissionTests(StageDPart3AReplayTests):
    """Part 3B1 reason-7 raw admission through open_current_raw_admission."""

    RAW_BOARD = "boards.example"
    RAW_JOB_ID = "j-1"
    RAW_URL = "https://boards.example/listing/j-1"
    RAW_TEXT = "Senior backend engineer role with Python, SQLite, and queues."
    RAW_JSON_TEXT = (
        '{"title": "Senior Backend Engineer",'
        ' "team": {"site": "berlin"},'
        ' "tags": ["python", "sqlite"]}'
    )

    POSTINGS_DDL = (
        "CREATE TABLE IF NOT EXISTS postings ("
        " key TEXT PRIMARY KEY, board TEXT NOT NULL, job_id TEXT NOT NULL,"
        " url TEXT NOT NULL, posted_at TEXT,"
        " first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        " last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        " fetched_at TEXT, raw_text TEXT, raw_json TEXT, content_hash TEXT,"
        " fetch_status TEXT NOT NULL DEFAULT 'discovered', fetch_error TEXT)"
    )

    def _payload(self, world: dict, main_db: pathlib.Path, vac_db: pathlib.Path,
                 *, track: str = "backend") -> dict:
        payload = super()._payload(world, main_db, vac_db, track=track)
        self._apply_raw_binding(payload)
        return payload

    def _apply_raw_binding(self, payload: dict, **overrides) -> tuple:
        board = overrides.pop("board", self.RAW_BOARD)
        job_id = overrides.pop("job_id", self.RAW_JOB_ID)
        url = overrides.pop("url", self.RAW_URL)
        posted_at = overrides.pop("posted_at", None)
        fetched_at = overrides.pop("fetched_at", self.RECEIPT_T)
        raw_text = overrides.pop("raw_text", self.RAW_TEXT)
        raw_json_text = overrides.pop("raw_json_text", self.RAW_JSON_TEXT)
        if overrides:
            raise TypeError(f"unknown raw overrides: {sorted(overrides)}")
        parsed = json.loads(raw_json_text) if raw_json_text is not None else None
        semantic = {
            "job_key": payload["job_key"],
            "board": board,
            "job_id": job_id,
            "url": url,
            "posted_at": posted_at,
            "fetched_at": fetched_at,
            "raw_text": raw_text,
            "raw_json": parsed,
            "fetch_status": "fetched",
        }
        source_sha = hashlib.sha256(
            ((raw_text or "") + (raw_json_text or "")).encode("utf-8")
        ).hexdigest()
        snapshot_sha = hashlib.sha256(
            processing_module.canonical_json(semantic).encode("utf-8")
        ).hexdigest()
        payload["raw"] = {
            "source_content_sha256": source_sha,
            "raw_snapshot_sha256": snapshot_sha,
        }
        output = payload["extraction"]["output"]
        output["source_content_sha256"] = source_sha
        payload["extraction"]["receipt"]["output_sha256"] = hashlib.sha256(
            processing_module.canonical_json(output).encode("utf-8")
        ).hexdigest()
        return (
            payload["job_key"],
            board,
            job_id,
            url,
            posted_at,
            fetched_at,
            raw_text,
            raw_json_text,
            source_sha,
            "fetched",
        )

    def _seed_posting(self, world: dict, payload: dict, **overrides) -> tuple:
        row = self._apply_raw_binding(payload, **overrides)
        self._insert_row_values(world, row)
        return row

    def _insert_row_values(self, world: dict, row: tuple) -> None:
        vac_db = world["data"] / "state" / "vacancies.sqlite3"
        conn = sqlite3.connect(vac_db)
        try:
            conn.execute(self.POSTINGS_DDL)
            conn.execute(
                "INSERT INTO postings"
                "(key,board,job_id,url,posted_at,fetched_at,raw_text,"
                "raw_json,content_hash,fetch_status)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                row,
            )
            conn.commit()
        finally:
            conn.close()

    def _ensure_postings_table(self, world: dict) -> None:
        vac_db = world["data"] / "state" / "vacancies.sqlite3"
        conn = sqlite3.connect(vac_db)
        try:
            conn.execute(self.POSTINGS_DDL)
            conn.commit()
        finally:
            conn.close()

    def _restage(self, world: dict, payload: dict) -> str:
        payload.pop("_staged_name", None)
        return self._stage(world, payload)

    def _semantic_node(self, **overrides) -> dict:
        node = {
            "job_key": "boards.example:j-1",
            "board": self.RAW_BOARD,
            "job_id": self.RAW_JOB_ID,
            "url": self.RAW_URL,
            "posted_at": None,
            "fetched_at": self.RECEIPT_T,
            "raw_text": self.RAW_TEXT,
            "raw_json": {"title": "Senior Backend Engineer"},
            "fetch_status": "fetched",
        }
        node.update(overrides)
        return node

    def _rekeyed_payload(
        self, world: dict, main_db: pathlib.Path, vac_db: pathlib.Path,
        *, board: str, job_id: str,
    ) -> tuple[dict, tuple]:
        payload = super()._payload(world, main_db, vac_db)
        payload["job_key"] = f"{board}:{job_id}"
        alignment_output = payload["alignment"]["output"]
        alignment_output["job_key"] = payload["job_key"]
        payload["alignment"]["receipt"]["output_sha256"] = hashlib.sha256(
            processing_module.canonical_json(alignment_output).encode("utf-8")
        ).hexdigest()
        payload["scoring"]["expected_score"]["job_key"] = payload["job_key"]
        row = self._apply_raw_binding(payload, board=board, job_id=job_id)
        return payload, row

    @staticmethod
    def _json_chain(depth_arrays: int) -> str:
        inner = "1"
        for _ in range(depth_arrays):
            inner = f"[{inner}]"
        return '{"data": ' + inner + "}"

    @staticmethod
    def _int_list(count: int) -> str:
        return '{"data": [' + ",".join(str(i % 10) for i in range(count)) + "]}"

    def _update_row(self, world: dict, statement: str, *params) -> None:
        vac_db = world["data"] / "state" / "vacancies.sqlite3"
        conn = sqlite3.connect(vac_db)
        try:
            conn.execute(statement, params)
            conn.commit()
        finally:
            conn.close()

    def _update_vacancy(self, world: dict, statement: str, *params) -> None:
        self._update_row(world, statement, *params)

    def _update_main(self, world: dict, statement: str, *params) -> None:
        main_db = world["data"] / "state" / "assessments.sqlite3"
        conn = sqlite3.connect(main_db)
        try:
            conn.execute(statement, params)
            conn.commit()
        finally:
            conn.close()

    def _counting_read_posting(self) -> list:
        calls: list = []
        original = processing_module.read_posting

        def spy(connection, *, key, schema="main"):
            calls.append((schema, key))
            return original(connection, key=key, schema=schema)

        processing_module.read_posting = spy
        self.addCleanup(setattr, processing_module, "read_posting", original)
        return calls

    def _open_raw(self, world: dict, name: str, payload: dict):
        return processing_module.open_current_raw_admission(
            world["data"], name, **self._cli(payload)
        )

    # ------------------------------------------------------------------
    # Positives
    # ------------------------------------------------------------------

    def test_definitive_absence_admits_immutable_raw_facts(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)

        baseline = _fd_count()
        with self._open_raw(world, name, payload) as lease:
            self.assertIsInstance(lease, pm._AdmissionLease)
            self.assertIsInstance(lease.raw, pm.RawSnapshotFacts)
            self.assertEqual(lease.raw.job_key, payload["job_key"])
            self.assertEqual(lease.raw.board, self.RAW_BOARD)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                lease.raw.job_key = "mutated"
        self.assertEqual(_fd_count(), baseline)

    def test_retained_provisional_keeps_detail_and_admits_raw(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        sealed = self._seed_exact(world, payload)
        mutable = bytearray(sealed)
        mutable[-20] ^= 0x01
        self._update_main(
            world,
            "UPDATE processing_receipts SET receipt_bytes=?",
            *(bytes(mutable),),
        )
        self._seed_posting(world, payload)
        name = self._restage(world, payload)
        with self._open_raw(world, name, payload) as lease:
            self.assertIsNotNone(lease.provisional_detail)
            self.assertIn("independent validation", lease.provisional_detail)
            self.assertIsInstance(lease.raw, pm.RawSnapshotFacts)

    def test_null_and_object_raw_json_and_verbatim_text(self) -> None:
        for variant in ("object", "null", "verbatim", "text_null"):
            with self.subTest(variant=variant):
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                if variant == "null":
                    self._seed_posting(world, payload, raw_json_text=None)
                elif variant == "verbatim":
                    text = '  {"a": 1,  "b":[1 ,2]}  '
                    self._seed_posting(world, payload, raw_json_text=text)
                elif variant == "text_null":
                    self._seed_posting(world, payload, raw_text=None)
                else:
                    self._seed_posting(world, payload)
                name = self._stage(world, payload)
                with self._open_raw(world, name, payload) as lease:
                    if variant == "null":
                        self.assertIsNone(lease.raw.raw_json_text)
                        self.assertEqual(lease.raw.raw_text, self.RAW_TEXT)
                    elif variant == "verbatim":
                        self.assertEqual(
                            lease.raw.raw_json_text,
                            '  {"a": 1,  "b":[1 ,2]}  ',
                        )
                    elif variant == "text_null":
                        self.assertIsNone(lease.raw.raw_text)
                        self.assertEqual(
                            lease.raw.raw_json_text, self.RAW_JSON_TEXT
                        )
                    else:
                        self.assertEqual(
                            json.loads(lease.raw.raw_json_text)["title"],
                            "Senior Backend Engineer",
                        )
                    material = (lease.raw.raw_text or "") + (
                        lease.raw.raw_json_text or ""
                    )
                    self.assertEqual(
                        hashlib.sha256(material.encode("utf-8")).hexdigest(),
                        lease.raw.source_content_sha256,
                    )

    def test_exact_boundary_fields_are_accepted(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(
            world, payload, url="u", raw_text="", posted_at=None
        )
        name = self._stage(world, payload)
        with self._open_raw(world, name, payload) as lease:
            self.assertEqual(lease.raw.url, "u")
            self.assertEqual(lease.raw.raw_text, "")
            self.assertIsNone(lease.raw.posted_at)

    def test_semantic_canonical_has_no_trailing_newline(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)
        with self._open_raw(world, name, payload) as lease:
            self.assertFalse(lease.raw.semantic_canonical.endswith(b"\n"))
            self.assertEqual(
                hashlib.sha256(lease.raw.semantic_canonical).hexdigest(),
                lease.raw.raw_snapshot_sha256,
            )

    def test_prose_control_characters_are_admitted(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        prose = "line one\nline two\tindented\rcarriage return"
        self._seed_posting(world, payload, raw_text=prose)
        name = self._stage(world, payload)
        with self._open_raw(world, name, payload) as lease:
            self.assertEqual(lease.raw.raw_text, prose)

    def test_control_characters_in_raw_text_are_refused(self) -> None:
        for label, character in (
            ("NUL", "\x00"),
            ("VT", "\x0b"),
            ("FF", "\x0c"),
            ("DEL", "\x7f"),
        ):
            with self.subTest(character=label):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_row(
                    world,
                    "UPDATE postings SET raw_text=?",
                    *(f"bad{character}text",),
                )
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )

    def test_controls_in_url_and_timestamp_fields_are_refused(self) -> None:
        cases = {
            "url": ("UPDATE postings SET url=?", ("https://x/\x01y",)),
            "posted_at": (
                "UPDATE postings SET posted_at=?",
                ("\x01" * 20,),
            ),
            "fetched_at": (
                "UPDATE postings SET fetched_at=?",
                ("2026-08-25T12:00:00\nZ",),
            ),
        }
        for label, (statement, params) in cases.items():
            with self.subTest(field=label):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_row(world, statement, *params)
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )

    def test_exact_url_and_timestamp_bounds_current_row(self) -> None:
        pm = processing_module

        url_edge = self._new_world()
        main_db, vac_db = self._databases(url_edge, canonical_store=False)
        payload = self._payload(url_edge, main_db, vac_db)
        self._seed_posting(url_edge, payload, url="u" * 4096)
        name = self._stage(url_edge, payload)
        with self._open_raw(url_edge, name, payload) as lease:
            self.assertEqual(len(lease.raw.url), 4096)

        over_url = self._new_world()
        main_db, vac_db = self._databases(over_url, canonical_store=False)
        payload = self._payload(over_url, main_db, vac_db)
        self._seed_posting(over_url, payload)
        self._update_row(
            over_url, "UPDATE postings SET url=?", *("u" * 4097,)
        )
        name = self._stage(over_url, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(over_url, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)

        max_stamp = "2026-08-25T12:00:00." + "1" * 43 + "Z"
        self.assertEqual(len(max_stamp), 64)
        stamp_edge = self._new_world()
        main_db, vac_db = self._databases(stamp_edge, canonical_store=False)
        payload = self._payload(stamp_edge, main_db, vac_db)
        self._seed_posting(stamp_edge, payload, posted_at=max_stamp)
        name = self._stage(stamp_edge, payload)
        with self._open_raw(stamp_edge, name, payload) as lease:
            self.assertEqual(lease.raw.posted_at, max_stamp)

        for label, statement, params in (
            ("length_65",
             "UPDATE postings SET posted_at=?",
             ("2026-08-25T12:00:00." + "1" * 44 + "Z",)),
            ("offset_hour_24",
             "UPDATE postings SET posted_at=?",
             ("2026-08-25T12:00:00+24:00",)),
        ):
            with self.subTest(case=label):
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_row(world, statement, *params)
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )

    def test_exact_board_and_job_id_upper_bounds_current_row(self) -> None:
        board = "B" * 128
        job_id = "J" * 127
        job_key = f"{board}:{job_id}"
        self.assertEqual(len(job_key), 256)

        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload, row = self._rekeyed_payload(
            world, main_db, vac_db, board=board, job_id=job_id
        )
        self._insert_row_values(world, row)
        name = self._stage(world, payload)
        with self._open_raw(world, name, payload) as lease:
            self.assertEqual(lease.raw.job_key, job_key)
            self.assertEqual(lease.raw.board, board)
            self.assertEqual(lease.raw.job_id, job_id)

    def test_depth_boundary_admitted_and_refused(self) -> None:
        """Wrapper object adds one level: scalar depth = arrays + 2, so 62
        nested arrays sit exactly at the contracted depth limit."""

        pm = processing_module

        edge_world = self._new_world()
        main_db, vac_db = self._databases(edge_world, canonical_store=False)
        payload = self._payload(edge_world, main_db, vac_db)
        self._seed_posting(
            edge_world, payload, raw_json_text=self._json_chain(62)
        )
        name = self._stage(edge_world, payload)
        with self._open_raw(edge_world, name, payload) as lease:
            node = json.loads(lease.raw.raw_json_text)["data"]
            depth = 0
            while isinstance(node, list):
                depth += 1
                node = node[0]
            self.assertEqual(depth, 62)

        over_world = self._new_world()
        main_db, vac_db = self._databases(over_world, canonical_store=False)
        payload = self._payload(over_world, main_db, vac_db)
        self._seed_posting(
            over_world, payload, raw_json_text=self._json_chain(63)
        )
        name = self._stage(over_world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(over_world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("depth", refused.exception.detail)

    def test_node_count_boundary_admitted_and_refused(self) -> None:
        """Wrapper object counts once: {"data": [k ints]} holds k+2 nodes."""

        pm = processing_module

        edge_world = self._new_world()
        main_db, vac_db = self._databases(edge_world, canonical_store=False)
        payload = self._payload(edge_world, main_db, vac_db)
        self._seed_posting(
            edge_world, payload, raw_json_text=self._int_list(99_998)
        )
        name = self._stage(edge_world, payload)
        with self._open_raw(edge_world, name, payload) as lease:
            self.assertEqual(
                len(json.loads(lease.raw.raw_json_text)["data"]), 99_998
            )

        over_world = self._new_world()
        main_db, vac_db = self._databases(over_world, canonical_store=False)
        payload = self._payload(over_world, main_db, vac_db)
        self._seed_posting(
            over_world, payload, raw_json_text=self._int_list(99_999)
        )
        name = self._stage(over_world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(over_world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("JSON nodes", refused.exception.detail)

    def test_primitive_substitution_reason7_matrix_all_columns(self) -> None:
        blob = sqlite3.Binary(b"\x00\x01blob")
        cases = {
            "key": ("UPDATE postings SET key=?", (blob,), "missing"),
            "board": ("UPDATE postings SET board=?", (blob,), "board"),
            "job_id": ("UPDATE postings SET job_id=?", (blob,), "job_id"),
            "url": ("UPDATE postings SET url=?", (blob,), "url"),
            "posted_at": ("UPDATE postings SET posted_at=?", (blob,), "posted_at"),
            "fetched_at": ("UPDATE postings SET fetched_at=?", (blob,), "fetched_at"),
            "raw_text": ("UPDATE postings SET raw_text=?", (blob,), "raw_text"),
            "raw_json": ("UPDATE postings SET raw_json=?", (blob,), "raw_json"),
            "content_hash": ("UPDATE postings SET content_hash=?", (blob,), "content_hash"),
            "fetch_status": ("UPDATE postings SET fetch_status=?", (blob,), "fetch_status"),
        }
        for column, (statement, params, fragment) in cases.items():
            with self.subTest(column=column):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_row(world, statement, *params)
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )
                if column == "key":
                    self.assertIn("missing", refused.exception.detail)
                else:
                    self.assertIn(
                        f"posting column {column} has primitive type bytes",
                        refused.exception.detail,
                    )

    def test_raw_json_scalar_toplevel_is_reason7(self) -> None:
        for label, text in (
            ("number", "42"),
            ("string", '"hello"'),
            ("bool", "true"),
        ):
            with self.subTest(scalar=label):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_row(
                    world, "UPDATE postings SET raw_json=?", *(text,)
                )
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )
                self.assertIn(
                    "stored raw_json TEXT must strict-parse to null or an object",
                    refused.exception.detail,
                )

    def test_nested_decoded_controls_in_raw_json_are_reason7(self) -> None:
        payloads = {
            "object_key_control": {"ti\x00tle": "x"},
            "string_value_control": {"title": "a\x01b"},
            "list_element_control": {"tags": ["ok", "bad\x02"]},
        }
        for label, node in payloads.items():
            with self.subTest(where=label):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_row(
                    world,
                    "UPDATE postings SET raw_json=?",
                    *(json.dumps(node),),
                )
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )
                self.assertIn(
                    "rejects control character", refused.exception.detail
                )

    def test_after_raw_read_vacancy_file_replacement_refuses_reason5(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)
        backup = vac_db.with_name("vacancies.sqlite3.matrix-bak")

        def replace_vacancy_file() -> None:
            os.rename(vac_db, backup)
            vac_db.write_bytes(b"replacement-inode")

        baseline = _fd_count()
        try:
            pm.install_fault("after_raw_read", replace_vacancy_file)
            with self.assertRaises(pm.ProcessingRefused) as refused:
                with self._open_raw(world, name, payload):
                    pass
            self.assertEqual(
                refused.exception.reason, pm.REASON_CONFIG_DATABASE
            )
        finally:
            pm.clear_faults()
            if backup.exists():
                os.rename(backup, vac_db)
        self.assertEqual(_fd_count(), baseline)

    def test_after_raw_read_state_ancestor_replacement_refuses_reason5(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)
        state_dir = world["data"] / "state"
        ancestor_backup = pathlib.Path(str(state_dir) + ".matrix-ancestor")

        def replace_state_ancestor() -> None:
            os.rename(state_dir, ancestor_backup)
            state_dir.mkdir()

        baseline = _fd_count()
        try:
            pm.install_fault("after_raw_read", replace_state_ancestor)
            with self.assertRaises(pm.ProcessingRefused) as refused:
                with self._open_raw(world, name, payload):
                    pass
            self.assertEqual(
                refused.exception.reason, pm.REASON_CONFIG_DATABASE
            )
        finally:
            pm.clear_faults()
            if ancestor_backup.exists():
                shutil.rmtree(state_dir, ignore_errors=True)
                os.rename(ancestor_backup, state_dir)
        self.assertEqual(_fd_count(), baseline)

    def test_max_raw_text_boundary_4000000_admitted_4000001_refused(self) -> None:
        pm = processing_module

        edge_world = self._new_world()
        main_db, vac_db = self._databases(edge_world, canonical_store=False)
        payload = self._payload(edge_world, main_db, vac_db)
        self._seed_posting(edge_world, payload, raw_text="a" * 4_000_000)
        name = self._stage(edge_world, payload)
        baseline = _fd_count()
        with self._open_raw(edge_world, name, payload) as lease:
            self.assertEqual(len(lease.raw.raw_text), 4_000_000)
        self.assertEqual(_fd_count(), baseline)

        over_world = self._new_world()
        main_db, vac_db = self._databases(over_world, canonical_store=False)
        payload = self._payload(over_world, main_db, vac_db)
        self._seed_posting(over_world, payload, raw_text="a" * 4_000_001)
        name = self._stage(over_world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(over_world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("posting.raw_text", refused.exception.detail)

    def test_semantic_shape_owner_enforces_unreachable_field_bounds(self) -> None:
        """Board/job_id bounds+controls are gated by envelope identity first;
        the owner shape validator is asserted directly for those rules."""

        validate = processing_module.validate_semantic_posting_shape
        base = self._semantic_node()

        self.assertEqual(validate(base)["board"], self.RAW_BOARD)
        for label, overrides in (
            ("board_129", {"board": "B" * 129}),
            ("board_nul", {"board": "boar\x00d"}),
            ("job_id_257", {"job_id": "J" * 257}),
            ("job_id_del", {"job_id": "j\x7f"}),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    validate(self._semantic_node(**overrides))

    # ------------------------------------------------------------------
    # Reason 7 negatives
    # ------------------------------------------------------------------

    def test_missing_posting_is_reason7(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._ensure_postings_table(world)
        name = self._stage(world, payload)
        baseline = _fd_count()
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("missing", refused.exception.detail)
        self.assertEqual(_fd_count(), baseline)

    def test_reason7_negative_matrix(self) -> None:
        cases = {
            "status_discovered": (
                "UPDATE postings SET fetch_status='discovered'", (),
            ),
            "wrong_type_url": ("UPDATE postings SET url=12345", ()),
            "blob_raw_text": (
                "UPDATE postings SET raw_text=?",
                (sqlite3.Binary(b"\x00\x01"),),
            ),
            "identity_binding": ("UPDATE postings SET board='other'", ()),
            "uppercase_hash": (
                "UPDATE postings SET content_hash=upper(content_hash)", ()
            ),
            "hash_not_computed": (
                "UPDATE postings SET content_hash=?", ("a" * 64,)
            ),
            "invalid_json": ("UPDATE postings SET raw_json='{oops'", ()),
            "duplicate_keys": (
                "UPDATE postings SET raw_json='{\"a\":1,\"a\":2}'", ()
            ),
            "nonfinite_json": ("UPDATE postings SET raw_json='{\"v\":NaN}'", ()),
            "array_json": ("UPDATE postings SET raw_json='[]'", ()),
            "naive_posted_at": (
                "UPDATE postings SET posted_at='2026-08-25T12:00:00'", ()
            ),
            "missing_fetched_at": ("UPDATE postings SET fetched_at=NULL", ()),
        }
        for label, (statement, params) in cases.items():
            with self.subTest(case=label):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                self._update_vacancy(world, statement, *params)
                name = self._stage(world, payload)
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )

    def test_hash_binds_row_but_not_staged_source(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        new_source = hashlib.sha256(b"unrelated-staged-source").hexdigest()
        output = payload["extraction"]["output"]
        output["source_content_sha256"] = new_source
        payload["extraction"]["receipt"]["output_sha256"] = hashlib.sha256(
            processing_module.canonical_json(output).encode("utf-8")
        ).hexdigest()
        payload["raw"] = {
            "source_content_sha256": new_source,
            "raw_snapshot_sha256": payload["raw"]["raw_snapshot_sha256"],
        }
        name = self._stage(world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("staged raw source binding", refused.exception.detail)

    def test_staged_snapshot_hash_mismatch_is_reason7(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        payload["raw"] = {
            "source_content_sha256": payload["raw"]["source_content_sha256"],
            "raw_snapshot_sha256": "d" * 64,
        }
        name = self._stage(world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("raw_snapshot_sha256", refused.exception.detail)

    def test_after_raw_read_update_and_delete_drift(self) -> None:
        for mode in ("update", "delete"):
            with self.subTest(mode=mode):
                pm = processing_module
                world = self._new_world()
                main_db, vac_db = self._databases(world, canonical_store=False)
                payload = self._payload(world, main_db, vac_db)
                self._seed_posting(world, payload)
                name = self._stage(world, payload)
                target = world["data"] / "state" / "vacancies.sqlite3"

                if mode == "update":
                    def action() -> None:
                        conn = sqlite3.connect(target)
                        try:
                            conn.execute(
                                "UPDATE postings SET raw_text='drifted'"
                            )
                            conn.commit()
                        finally:
                            conn.close()
                else:
                    def action() -> None:
                        conn = sqlite3.connect(target)
                        try:
                            conn.execute("DELETE FROM postings")
                            conn.commit()
                        finally:
                            conn.close()

                pm.install_fault("after_raw_read", action)
                self.addCleanup(pm.clear_faults)
                baseline = _fd_count()
                with self.assertRaises(pm.ProcessingRefused) as refused:
                    with self._open_raw(world, name, payload):
                        pass
                self.assertEqual(
                    refused.exception.reason, pm.REASON_RAW_SNAPSHOT
                )
                if mode == "delete":
                    self.assertIn("drifted between read and immediate reread",
                                  refused.exception.detail)
                self.assertEqual(_fd_count(), baseline)

    def test_reason7_beats_retained_provisional(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=True)
        payload = self._payload(world, main_db, vac_db)
        sealed = self._seed_exact(world, payload)
        mutable = bytearray(sealed)
        mutable[-20] ^= 0x01
        self._update_main(
            world,
            "UPDATE processing_receipts SET receipt_bytes=?",
            *(bytes(mutable),),
        )
        self._ensure_postings_table(world)
        name = self._restage(world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)

    # ------------------------------------------------------------------
    # Shadowing, zero-read, cleanup, authorizer, revalidate_raw
    # ------------------------------------------------------------------

    def test_main_postings_shadow_is_never_consulted(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._ensure_postings_table(world)
        valid_row = self._apply_raw_binding(payload)
        conn = sqlite3.connect(main_db)
        try:
            conn.execute(self.POSTINGS_DDL)
            conn.execute(
                "INSERT INTO postings"
                "(key,board,job_id,url,posted_at,fetched_at,raw_text,"
                "raw_json,content_hash,fetch_status)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                valid_row,
            )
            conn.commit()
        finally:
            conn.close()
        name = self._stage(world, payload)
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(world, name, payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_RAW_SNAPSHOT)
        self.assertIn("missing", refused.exception.detail)

    def test_exact_replay_and_reason6_invoke_zero_reads(self) -> None:
        calls = self._counting_read_posting()
        pm = processing_module

        exact_world = self._new_world()
        main_db, vac_db = self._databases(exact_world, canonical_store=True)
        payload = self._payload(exact_world, main_db, vac_db)
        sealed = self._seed_exact(exact_world, payload)
        name = self._restage(exact_world, payload)
        with self._open_raw(exact_world, name, payload) as yielded:
            self.assertIsInstance(yielded, pm.ReplayClassification)
            self.assertEqual(yielded.disposition, "exact_replay")
            self.assertEqual(yielded.stored_receipt_bytes, sealed)
        self.assertEqual(calls, [])

        mismatch_world = self._new_world()
        main_db, vac_db = self._databases(mismatch_world, canonical_store=True)
        other_payload = self._payload(mismatch_world, main_db, vac_db)
        self._seed_exact(mismatch_world, other_payload)
        changed = copy.deepcopy(other_payload)
        changed.pop("_staged_name", None)
        changed["scoring"]["expected_score"]["final"] = (
            float(changed["scoring"]["expected_score"]["final"]) + 0.25
        )
        changed_facts = self._facts(mismatch_world, changed)
        _b, changed_binding = pm.build_processing_binding_from_facts(changed_facts)
        receipt2, _sealed2 = self._build_receipt(
            changed, changed_facts, changed_binding
        )
        sealed2 = pm.sealed_receipt_bytes(receipt2)
        conn = sqlite3.connect(main_db)
        try:
            conn.execute("DELETE FROM processing_receipts")
            conn.execute(
                "INSERT INTO processing_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    receipt2["operation_id"],
                    receipt2["profile_id"],
                    receipt2["job_key"],
                    receipt2["track"],
                    changed_binding,
                    changed_facts.envelope_file_sha256,
                    changed_facts.envelope_semantic_sha256,
                    receipt2["normalised_projection"]["normalized_json_sha256"],
                    receipt2["assessment_projection"]["score_payload_hash"],
                    1,
                    receipt2["self_hash"],
                    hashlib.sha256(sealed2).hexdigest(),
                    sealed2,
                    receipt2["created_at"],
                ),
            )
            conn.commit()
        finally:
            conn.close()
        staged_name = other_payload["_staged_name"]
        with self.assertRaises(pm.ProcessingRefused) as refused:
            with self._open_raw(mismatch_world, staged_name, other_payload):
                pass
        self.assertEqual(refused.exception.reason, pm.REASON_EXISTING_RECEIPT)
        self.assertEqual(calls, [])

    def test_lease_closes_connection_and_descriptors(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)
        baseline = _fd_count()
        holder = {}
        with self._open_raw(world, name, payload) as lease:
            holder["lease"] = lease
            self.assertIsNotNone(lease.connection)
        lease = holder["lease"]
        self.assertIsNone(lease.connection)
        self.assertEqual(lease.descriptors.leaves, [])
        self.assertEqual(lease.descriptors.db_leaves, [])
        self.assertEqual(_fd_count(), baseline)

    def test_query_only_authorizer_and_nowrite_on_raw_path(self) -> None:
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)

        allowed_pragmas = {
            "query_only",
            "database_list",
            "index_list",
            "index_info",
            "foreign_key_list",
        }
        denied: list = []

        def authorizer(action, arg1, _arg2, _db, _source):
            s = sqlite3
            if action in (
                s.SQLITE_SELECT,
                s.SQLITE_READ,
                s.SQLITE_FUNCTION,
                s.SQLITE_RECURSIVE,
            ):
                return s.SQLITE_OK
            if action == s.SQLITE_PRAGMA:
                if arg1 in allowed_pragmas:
                    return s.SQLITE_OK
                denied.append((action, str(arg1)))
                return s.SQLITE_DENY
            if action == s.SQLITE_ATTACH:
                return s.SQLITE_OK
            denied.append((action, str(arg1)))
            return s.SQLITE_DENY

        baseline = _fd_count()
        with contextlib.closing(sqlite3.connect(main_db)) as conn:
            before_main = list(conn.iterdump())
        with contextlib.closing(sqlite3.connect(vac_db)) as conn:
            before_vac = list(conn.iterdump())
        with self._open_raw(world, name, payload) as lease:
            lease.connection.set_authorizer(authorizer)
            lease.revalidate_raw()
        with contextlib.closing(sqlite3.connect(main_db)) as conn:
            after_main = list(conn.iterdump())
        with contextlib.closing(sqlite3.connect(vac_db)) as conn:
            after_vac = list(conn.iterdump())
        self.assertEqual(before_main, after_main)
        self.assertEqual(before_vac, after_vac)
        self.assertEqual(denied, [])
        self.assertEqual(_fd_count(), baseline)

    def test_revalidate_raw_happy_and_drift(self) -> None:
        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=False)
        payload = self._payload(world, main_db, vac_db)
        self._seed_posting(world, payload)
        name = self._stage(world, payload)
        with self._open_raw(world, name, payload) as lease:
            self.assertIsNone(lease.revalidate_raw())
            self.assertIsNone(lease.revalidate_raw())
            self._update_vacancy(
                world,
                "UPDATE postings SET fetched_at=?",
                *("2026-08-25T13:00:00.000000Z",),
            )
            with self.assertRaises(pm.ProcessingRefused) as refused:
                lease.revalidate_raw()
            self.assertEqual(
                refused.exception.reason, pm.REASON_RAW_SNAPSHOT
            )


class StageDReadPostingOwnerTests(TempRootTestCase):
    """Owner tests for state.vacancies.read_posting contract."""

    KEY = "boards.example:j-1"

    @staticmethod
    def _row_values(schema_tag: str) -> tuple:
        return (
            "boards.example:j-1",
            "boards.example",
            "j-1",
            f"https://boards.example/listing/j-1?via={schema_tag}",
            None,
            "2026-08-25T12:00:00.000000Z",
            f"text-from-{schema_tag}",
            '{"schema_tag": "%s"}' % schema_tag,
            hashlib.sha256(f"text-from-{schema_tag}".encode()).hexdigest(),
            "fetched",
        )

    def _attached(self):
        from market_aligner.state import vacancies as vacancies_module

        root = pathlib.Path(self.root) / "owner"
        root.mkdir(parents=True, exist_ok=True)
        main_db = root / "assessments.sqlite3"
        vac_db = root / "vacancies.sqlite3"
        for target in (main_db, vac_db):
            conn = sqlite3.connect(target)
            try:
                conn.executescript(vacancies_module.SCHEMA)
                conn.commit()
            finally:
                conn.close()
        conn = sqlite3.connect(main_db)
        conn.execute("ATTACH DATABASE ? AS vacancy", (str(vac_db),))
        self.addCleanup(conn.close)
        return vacancies_module, main_db, vac_db, conn

    def _seed_both(self, conn) -> None:
        columns = (
            "(key,board,job_id,url,posted_at,fetched_at,raw_text,"
            "raw_json,content_hash,fetch_status)"
        )
        conn.execute(
            f"INSERT INTO postings {columns} VALUES(?,?,?,?,?,?,?,?,?,?)",
            self._row_values("main"),
        )
        conn.execute(
            f"INSERT INTO vacancy.postings {columns} VALUES(?,?,?,?,?,?,?,?,?,?)",
            self._row_values("vacancy"),
        )
        conn.commit()

    def test_default_schema_reads_main(self) -> None:
        vacancies_module, _main, _vac, conn = self._attached()
        self._seed_both(conn)
        row = vacancies_module.read_posting(conn, key=self.KEY)
        self.assertIsNotNone(row)
        self.assertEqual(row["url"], "https://boards.example/listing/j-1?via=main")

    def test_explicit_vacancy_schema_reads_attached_database(self) -> None:
        vacancies_module, _main, _vac, conn = self._attached()
        self._seed_both(conn)
        row = vacancies_module.read_posting(conn, key=self.KEY, schema="vacancy")
        self.assertIsNotNone(row)
        self.assertEqual(
            row["url"], "https://boards.example/listing/j-1?via=vacancy"
        )

    def test_invalid_schema_is_refused(self) -> None:
        vacancies_module, _main, _vac, conn = self._attached()
        for bad in ("temp", "", "VACANCY", "main;", "vacancy--", "main "):
            with self.subTest(schema=bad):
                with self.assertRaises(ValueError):
                    vacancies_module.read_posting(conn, key=self.KEY, schema=bad)

    def test_exact_projected_columns_and_row_type(self) -> None:
        vacancies_module, _main, _vac, conn = self._attached()
        self._seed_both(conn)
        row = vacancies_module.read_posting(conn, key=self.KEY)
        self.assertIsInstance(row, sqlite3.Row)
        self.assertEqual(
            tuple(row.keys()), tuple(vacancies_module.POSTING_READ_COLUMNS)
        )
        self.assertEqual(row["fetch_status"], "fetched")
        self.assertNotIn("fetch_error", row.keys())
        self.assertNotIn("first_seen_at", row.keys())

    def test_missing_key_returns_none(self) -> None:
        vacancies_module, _main, _vac, conn = self._attached()
        self.assertIsNone(vacancies_module.read_posting(conn, key="other:1"))
        self.assertIsNone(
            vacancies_module.read_posting(conn, key="other:1", schema="vacancy")
        )

    def test_connection_row_factory_is_untouched(self) -> None:
        vacancies_module, _main, _vac, conn = self._attached()
        self._seed_both(conn)
        self.assertIsNone(conn.row_factory)
        vacancies_module.read_posting(conn, key=self.KEY)
        row = vacancies_module.read_posting(conn, key=self.KEY)
        self.assertIsInstance(row, sqlite3.Row)
        self.assertIsNone(conn.row_factory)

        def tuple_factory(cursor, values):
            return tuple(values)

        conn.row_factory = tuple_factory
        row = vacancies_module.read_posting(conn, key=self.KEY)
        self.assertIsInstance(row, sqlite3.Row)
        self.assertIs(conn.row_factory, tuple_factory)


class StageDPart3B2SemanticUnitsTests(TempRootTestCase):
    """Seam-free reason 9-13 units over synthetic composed facts."""

    PROFILE_ID = "prf_" + "a" * 32
    JOB_KEY = "boards.example:j-1"
    TRACK = "backend"
    RECEIPT_T = "2026-08-25T12:00:00.000000Z"
    RAW_SOURCE = "a" * 64

    def _fixture_profile(self):
        from market_aligner.profiler.schema import CandidateProfile, TrackProfile

        return CandidateProfile(
            profile_id=self.PROFILE_ID,
            version="2024-01",
            tracks={
                "backend": TrackProfile(
                    interest=4,
                    demonstrated_skill=5,
                    confidence=0.9,
                    market_readiness=3,
                    evidence_ids=("ev-1",),
                    rationale="Backend evidence.",
                ),
                "research": TrackProfile(
                    interest=2,
                    demonstrated_skill=2,
                    confidence=0.5,
                    market_readiness=1,
                    evidence_ids=("ev-other",),
                    rationale="Research evidence.",
                ),
            },
        )

    def _fixture_evidence(self):
        from market_aligner.profiler.schema import EvidenceItem

        return {
            "ev-1": EvidenceItem(
                evidence_id="ev-1",
                kind="project",
                claim="Built a deterministic queue.",
                source_ref="private://portfolio/item-1",
                status="verified",
                confidence=0.9,
            ),
            "ev-other": EvidenceItem(
                evidence_id="ev-other",
                kind="paper",
                claim="Published queueing analysis.",
                source_ref="private://portfolio/item-2",
                status="verified",
                confidence=0.8,
            ),
        }

    def _raw_facts(self, **overrides):
        values = dict(
            job_key=self.JOB_KEY,
            board="boards.example",
            job_id="j-1",
            url="https://boards.example/listing/j-1",
            posted_at=None,
            fetched_at=self.RECEIPT_T,
            fetch_status="fetched",
            raw_text="Senior role body.",
            raw_json_text='{"team": "core"}',
            source_content_sha256=self.RAW_SOURCE,
            raw_snapshot_sha256="b" * 64,
            semantic_canonical=b"unused",
        )
        values.update(overrides)
        return processing_module.RawSnapshotFacts(**values)

    def _extraction_output(self, source: str):
        return {
            "source_content_sha256": source,
            "title": "Senior Backend Engineer",
            "company": "",
            "location": "",
            "description": "Owns services end to end.",
            "responsibilities": ["Ship queues"],
            "required_skills": ["Python"],
            "preferred_skills": [],
            "required_qualifications": [],
            "preferred_qualifications": [],
            "work_authorisation": [],
            "contract_type": "",
            "seniority": "",
            "remote_policy": "",
            "extraction_confidence": 0.9,
            "unknown_fields": [],
            "contract_version": processing_module.LLM_CONTRACT_VERSION,
        }

    def _alignment_output(self):
        return {
            "profile_id": self.PROFILE_ID,
            "profile_version": "2024-01",
            "job_key": self.JOB_KEY,
            "matches": [
                {
                    "requirement": "Own services end to end",
                    "evidence_ids": ["ev-1"],
                    "strength": 0.75,
                    "rationale": "Direct ownership evidence.",
                }
            ],
            "missing_requirements": [],
            "technical_alignment": 0.6,
            "evidence_match": 0.5,
            "confidence": 0.7,
            "unknowns": [],
            "contract_version": processing_module.LLM_CONTRACT_VERSION,
        }

    def _true_score(self, alignment_output: dict) -> dict:
        from market_aligner.assessment.scoring import (
            AssessmentAxes,
            ScoringParams,
        )

        axes = AssessmentAxes(
            technical_alignment=float(alignment_output["technical_alignment"]) * 10,
            evidence_match=float(alignment_output["evidence_match"]) * 10,
            market_demand=0,
            barrier_to_entry=10,
            growth_potential=0,
        )
        result = processing_module.deterministic_score(
            self._fixture_profile(),
            self.JOB_KEY,
            self.TRACK,
            axes,
            ScoringParams(),
        )
        return dataclasses.asdict(result)

    def _context(self):
        return {
            "schema": "market-aligner.profile-llm-context.v1",
            "tracks": {},
            "instruction": "Judge only from the supplied evidence.",
        }

    def _accepted_vacancy(self, raw, extraction_output, receipt_dict):
        posting = processing_module.RawPosting(
            board=raw.board,
            job_id=raw.job_id,
            url=raw.url,
            fetched_at=raw.fetched_at,
            raw_text=raw.raw_text,
            raw_json=(
                processing_module.strict_json_loads(raw.raw_json_text)
                if raw.raw_json_text is not None
                else None
            ),
            content_sha256=raw.source_content_sha256,
        )
        owner = processing_module._extraction_from_structural(
            processing_module._freeze_structure(extraction_output)
        )
        receipt = processing_module.LLMReceipt(**receipt_dict)
        return processing_module.accept_extraction(posting, owner, receipt)

    def _compose_consistent(self, **kwargs):
        """Compose with the alignment input hash wired to the true accepted
        vacancy so reasons 9 and 10 can both pass on the happy path."""

        raw = kwargs.pop("raw", None) or self._raw_facts()
        extraction_mutations = kwargs.pop("extraction_mutations", None) or {}
        receipt_overrides = kwargs.pop("receipt_overrides", None) or {}
        parsed_raw_json = (
            processing_module.strict_json_loads(raw.raw_json_text)
            if raw.raw_json_text is not None
            else None
        )
        extraction_input_sha = processing_module.canonical_hash(
            {
                "schema_version":
                    processing_module.EXTRACTION_INPUT_SCHEMA_VERSION,
                "job_key": raw.job_key,
                "board": raw.board,
                "job_id": raw.job_id,
                "url": raw.url,
                "fetched_at": raw.fetched_at,
                "source_content_sha256": raw.source_content_sha256,
                "raw_snapshot_sha256": raw.raw_snapshot_sha256,
                "raw_text": raw.raw_text,
                "raw_json": parsed_raw_json,
            }
        )
        extraction_output = self._extraction_output(raw.source_content_sha256)
        for path, value in extraction_mutations.items():
            node = extraction_output
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
        extraction_receipt = {
            "receipt_id": "rcpt-ex-1",
            "task": "semantic_vacancy_extraction",
            "model": "test-model",
            "prompt_version": "pv-1",
            "input_sha256": extraction_input_sha,
            "output_sha256": processing_module.canonical_hash(extraction_output),
            "created_at": self.RECEIPT_T,
            "contract_version": processing_module.LLM_CONTRACT_VERSION,
        }
        try:
            vacancy = self._accepted_vacancy(
                raw, extraction_output, extraction_receipt
            )
        except ValueError:
            # Owner-invalid staged prose cannot seed the alignment input;
            # wire against a self-consistent unmutated twin since such
            # fixtures stop at reason 9 and never reach reason 10.
            base_output = self._extraction_output(raw.source_content_sha256)
            base_receipt = {
                **extraction_receipt,
                "output_sha256": processing_module.canonical_hash(base_output),
            }
            vacancy = self._accepted_vacancy(raw, base_output, base_receipt)

        context = self._context()
        context_sha = processing_module.canonical_hash(context)
        alignment_output = self._alignment_output()
        for path, value in (kwargs.pop("alignment_mutations", None) or {}).items():
            node = alignment_output
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
        alignment_input_sha = processing_module.canonical_hash(
            {
                "schema_version":
                    processing_module.ALIGNMENT_INPUT_SCHEMA_VERSION,
                "job_key": self.JOB_KEY,
                "profile_id": self.PROFILE_ID,
                "profile_version": "2024-01",
                "track": self.TRACK,
                "vacancy": dataclasses.asdict(vacancy),
                "profile_context": context,
                "profile_context_sha256": context_sha,
            }
        )
        alignment_receipt = {
            "receipt_id": "rcpt-al-1",
            "task": "evidence_alignment",
            "model": "test-model",
            "prompt_version": "pv-1",
            "input_sha256": alignment_input_sha,
            "output_sha256": processing_module.canonical_hash(alignment_output),
            "created_at": self.RECEIPT_T,
            "contract_version": processing_module.LLM_CONTRACT_VERSION,
        }

        score_node = self._true_score(alignment_output)
        delete_marker = getattr(self, "SCORE_DELETE", None)
        for path, value in (kwargs.pop("score_mutations", None) or {}).items():
            node = score_node
            for key in path[:-1]:
                node = node[key]
            if delete_marker is not None and value is delete_marker:
                del node[path[-1]]
            else:
                node[path[-1]] = value

        payload = self._payload_skeleton(
            raw,
            context_sha,
            extraction_output,
            extraction_receipt,
            alignment_output,
            alignment_receipt,
            score_node,
            params_sha_override=kwargs.pop("params_sha_override", None),
            policy_sha_override=kwargs.pop("policy_sha_override", None),
        )
        for section, overrides_by_field in receipt_overrides.items():
            payload[section]["receipt"].update(overrides_by_field)
        file_sha = hashlib.sha256(
            processing_module.canonical_json(payload).encode("utf-8") + b"\n"
        ).hexdigest()
        facts = processing_module.compose_envelope_facts(
            payload,
            envelope_file_sha256=file_sha,
            expected_assessments_path=None,
            expected_vacancy_path=None,
        )
        return facts, payload, raw, context, context_sha, vacancy

    def _payload_skeleton(
        self,
        raw,
        context_sha,
        extraction_output,
        extraction_receipt,
        alignment_output,
        alignment_receipt,
        score_node,
        *,
        params_sha_override=None,
        policy_sha_override=None,
    ):
        return {
            "schema_version": processing_module.ENVELOPE_SCHEMA_VERSION,
            "operation_id": "op-12345678",
            "job_key": self.JOB_KEY,
            "profile_id": self.PROFILE_ID,
            "profile_version": "2024-01",
            "track": self.TRACK,
            "config": {
                "source_path": "/cfg/product.toml",
                "source_file_sha256": "c" * 64,
                "closure_files": {"/cfg/product.toml": "c" * 64},
                "closure_sha256": processing_module.canonical_hash(
                    {"/cfg/product.toml": "c" * 64}
                ),
                "semantic_sha256": "e" * 64,
            },
            "databases": {
                "assessments": {
                    "path": "/state/assessments.sqlite3",
                    "dev": 1, "ino": 222, "uid": os.getuid(),
                    "mode": 384, "nlink": 1,
                },
                "vacancy": {
                    "path": "/state/vacancies.sqlite3",
                    "dev": 1, "ino": 333, "uid": os.getuid(),
                    "mode": 384, "nlink": 1,
                },
            },
            "raw": {
                "source_content_sha256": raw.source_content_sha256,
                "raw_snapshot_sha256": raw.raw_snapshot_sha256,
            },
            "profile": {
                "profile_file_sha256": "1" * 64,
                "evidence_file_sha256": "2" * 64,
                "profile_sha256": "3" * 64,
                "evidence_ledger_sha256": "4" * 64,
                "profile_context_sha256": context_sha,
            },
            "extraction": {
                "output": extraction_output,
                "receipt": dict(extraction_receipt),
            },
            "alignment": {
                "output": alignment_output,
                "receipt": dict(alignment_receipt),
            },
            "scoring": {
                "parameters_sha256": params_sha_override
                or processing_module.ScoringParams().parameters_hash,
                "opportunity_policy_sha256": policy_sha_override
                or processing_module.OPPORTUNITY_POLICY_SHA256,
                "expected_score": score_node,
            },
        }

    class _FakeSnapshot:
        def __init__(self, test):
            self.profile = test._fixture_profile()
            self.evidence = test._fixture_evidence()
            self.context = test._context()
            self.hashes = {
                "profile_context_sha256":
                    processing_module.canonical_hash(self.context),
            }

    def _run_stages(self, facts, raw=None, snapshot=None):
        snapshot = snapshot or self._FakeSnapshot(self)
        admitted = processing_module._admit_extraction_stage(
            facts, raw or self._raw_facts()
        )
        vacancy = admitted.pop("vacancy")
        admitted.update(
            processing_module._admit_alignment_stage(facts, snapshot, vacancy)
        )
        accepted = admitted.pop("accepted_alignment")
        processing_module._admit_parameter_stage(facts)
        processing_module._admit_policy_stage(facts)
        tail = processing_module._admit_score_stage(
            facts, snapshot.profile, accepted
        )
        admitted.update(tail)
        return admitted

    def _refused_reason(self, callable_, reason):
        with self.assertRaises(processing_module.ProcessingRefused) as refused:
            callable_()
        self.assertEqual(refused.exception.reason, reason)
        return refused.exception

    # ------------------------------------------------------------ positives

    def test_policy_body_matches_contract_constant(self) -> None:
        self.assertEqual(
            processing_module.OPPORTUNITY_POLICY_SHA256,
            "65b4674413537ca5b151e1c9627585d025aedb3183c70dcae23de9c78e17e13d",
        )

    def test_freeze_preserves_primitive_types_and_builders_construct_owners(self) -> None:
        structural = processing_module._freeze_structure(
            {
                "float": 0.5,
                "int": 7,
                "bool": True,
                "none": None,
                "list": [1, 0.5],
                "nested": {"a": [{"b": 2}]},
            }
        )
        self.assertEqual(structural[0], ("bool", True))
        self.assertEqual(dict(structural)["float"], 0.5)
        self.assertIs(type(dict(structural)["int"]), int)
        self.assertIs(type(dict(structural)["list"][1]), float)
        self.assertIsInstance(dict(structural)["nested"][0][1][0], tuple)

        output = self._extraction_output(self.RAW_SOURCE)
        canonical = processing_module.canonical_json(output).encode("utf-8")
        structural = processing_module._freeze_structure(output)
        owner = processing_module._extraction_from_structural(structural)
        self.assertEqual(
            hashlib.sha256(
                processing_module.canonical_json(
                    dataclasses.asdict(owner)
                ).encode("utf-8")
            ).hexdigest(),
            hashlib.sha256(canonical).hexdigest(),
        )
        blank = processing_module._freeze_structure(
            self._extraction_output(self.RAW_SOURCE) | {"description": "   "}
        )
        with self.assertRaises(ValueError):
            processing_module._extraction_from_structural(blank)

        alignment_output = self._alignment_output()
        alignment = processing_module._alignment_from_structural(
            processing_module._freeze_structure(alignment_output)
        )
        self.assertEqual(alignment.matches[0].requirement,
                         "Own services end to end")
        blank_rationale = copy.deepcopy(alignment_output)
        blank_rationale["matches"][0]["rationale"] = " "
        with self.assertRaises(ValueError):
            processing_module._alignment_from_structural(
                processing_module._freeze_structure(blank_rationale)
            )

    # ------------------------------------------------- reason 9-13 stages

    def test_stages_happy_path_binds_exact_bytes_and_provenance(self) -> None:
        facts, payload, raw, context, context_sha, vacancy = (
            self._compose_consistent()
        )
        admitted = self._run_stages(facts, raw=raw)

        from market_aligner.llm.contracts import canonical_hash

        self.assertEqual(
            admitted["extraction_input_sha256"],
            canonical_hash(
                {
                    "schema_version":
                        processing_module.EXTRACTION_INPUT_SCHEMA_VERSION,
                    "job_key": raw.job_key,
                    "board": raw.board,
                    "job_id": raw.job_id,
                    "url": raw.url,
                    "fetched_at": raw.fetched_at,
                    "source_content_sha256": raw.source_content_sha256,
                    "raw_snapshot_sha256": raw.raw_snapshot_sha256,
                    "raw_text": raw.raw_text,
                    "raw_json": {"team": "core"},
                }
            ),
        )
        expected_normalized = json.dumps(
            dataclasses.asdict(vacancy),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(
            admitted["normalized_vacancy_bytes"], expected_normalized
        )
        self.assertFalse(admitted["normalized_vacancy_bytes"].endswith(b"\n"))
        self.assertEqual(
            hashlib.sha256(expected_normalized).hexdigest(),
            admitted["normalized_json_sha256"],
        )
        self.assertEqual(
            admitted["score_result_bytes"],
            processing_module.canonical_json(
                payload["scoring"]["expected_score"]
            ).encode("utf-8"),
        )
        self.assertEqual(
            admitted["parameters_sha256"],
            processing_module.ScoringParams().parameters_hash,
        )
        self.assertEqual(
            admitted["opportunity_policy_sha256"],
            "65b4674413537ca5b151e1c9627585d025aedb3183c70dcae23de9c78e17e13d",
        )

    def test_reason9_negatives_map_to_binding_extraction(self) -> None:
        cases = {
            "input_hash_mismatch": dict(
                receipt_overrides={
                    "extraction": {"input_sha256": "f" * 64}
                }
            ),
            "blank_owner_description": dict(
                extraction_mutations={("description",): "   "}
            ),
            "blank_owner_title": dict(
                extraction_mutations={("title",): "   "}
            ),
            "wrong_task": dict(
                receipt_overrides={"extraction": {"task": "evidence_alignment"}}
            ),
            "output_hash_unbound": dict(
                receipt_overrides={
                    "extraction": {"output_sha256": "e" * 64}
                }
            ),
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                facts, _p, raw, *_rest = self._compose_consistent(**kwargs)
                self._refused_reason(
                    lambda f=facts, r=raw: processing_module
                    ._admit_extraction_stage(f, r),
                    processing_module.REASON_EXTRACTION,
                )

    def test_reason10_negatives_map_to_binding_alignment(self) -> None:
        cases = {
            "other_track_citation": dict(
                alignment_mutations={
                    ("matches", 0, "evidence_ids"): ["ev-other"]
                }
            ),
            "unknown_citation": dict(
                alignment_mutations={
                    ("matches", 0, "evidence_ids"): ["ev-ghost"]
                }
            ),
            "identity_profile_version": dict(
                alignment_mutations={("profile_version",): "2024-02"}
            ),
            "identity_job_key": dict(
                alignment_mutations={("job_key",): "other.example:j"}
            ),
            "input_hash_mismatch": dict(
                receipt_overrides={"alignment": {"input_sha256": "f" * 64}}
            ),
            "wrong_task": dict(
                receipt_overrides={"alignment": {"task": "semantic_vacancy_extraction"}}
            ),
            "blank_owner_rationale": dict(
                alignment_mutations={("matches", 0, "rationale"): "  "}
            ),
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                facts, _p, raw, *_rest = self._compose_consistent(**kwargs)
                snapshot = self._FakeSnapshot(self)

                def probe(f=facts, s=snapshot):
                    admitted = processing_module._admit_extraction_stage(f, self._raw_facts())
                    vacancy = admitted.pop("vacancy")
                    processing_module._admit_alignment_stage(f, s, vacancy)

                self._refused_reason(
                    probe, processing_module.REASON_ALIGNMENT
                )

    def test_reason11_requires_both_parameter_hashes(self) -> None:
        for label, override, fragment in (
            ("staged", "9" * 64, "scoring.parameters_sha256"),
            ("expected", None, "expected_score.parameters_hash"),
        ):
            with self.subTest(which=label):
                if label == "expected":
                    facts, _p, raw, *_r = self._compose_consistent(
                        score_mutations={
                            ("parameters_hash",): "8" * 64,
                        }
                    )
                else:
                    facts, _p, raw, *_r = self._compose_consistent(
                        params_sha_override="9" * 64
                    )
                def probe(f=facts, r=raw):
                    admitted = processing_module._admit_extraction_stage(f, r)
                    vacancy = admitted.pop("vacancy")
                    snapshot = self._FakeSnapshot(self)
                    admitted.update(
                        processing_module._admit_alignment_stage(f, snapshot, vacancy)
                    )
                    admitted.pop("accepted_alignment")
                    processing_module._admit_parameter_stage(f)
                self._refused_reason(
                    probe, processing_module.REASON_SCORING_PARAMS
                )
                # The fragment distinction proves WHICH hash failed.
                try:
                    probe()
                except processing_module.ProcessingRefused as exc:
                    self.assertIn(fragment, exc.detail)

    def test_reason12_fixed_policy_only(self) -> None:
        facts, _p, raw, *_r = self._compose_consistent(
            policy_sha_override="7" * 64
        )
        self._refused_reason(
            lambda: processing_module._admit_policy_stage(facts),
            processing_module.REASON_OPPORTUNITY_POLICY,
        )

    SCORE_DELETE = object()

    def test_reason13_score_substitution_matrix_is_type_exact(self) -> None:
        true_score = self._true_score(self._alignment_output())

        def delta(field):
            return {("fit" if field == "fit" else field,):
                    float(true_score[field]) + 1e-9}

        r13_cases = {
            "profile_id_identity": {
                ("profile_id",): "prf_" + "b" * 32},
            "job_key_identity": {("job_key",): "other.example:j"},
            "track_identity": {("track",): "frontend"},
            "fit_delta": delta("fit"),
            "opportunity_delta": delta("opportunity"),
            "final_delta": delta("final"),
            "final_int_cast": {("final",): int(true_score["final"])},
            "fit_status_swap": {("fit_status",): "calibrated"},
            "market_demand_int_zero": {
                ("opportunity_subscores", "market_demand"): 0},
            "accessibility_int_zero": {
                ("opportunity_subscores", "accessibility"): 0},
            "growth_potential_int_zero": {
                ("opportunity_subscores", "growth_potential"): 0},
        }
        for key in sorted(true_score["fit_subscores"]):
            r13_cases[f"fit_subscore_{key}_delta"] = {
                ("fit_subscores", key): float(
                    true_score["fit_subscores"][key]
                ) + 1e-9,
            }
        for key in sorted(true_score["opportunity_subscores"]):
            if key == "market_demand":
                continue
            r13_cases[f"opportunity_subscore_{key}_delta"] = {
                ("opportunity_subscores", key): float(
                    true_score["opportunity_subscores"][key]
                ) + 1e-9,
            }
        for label, mutations in r13_cases.items():
            with self.subTest(case=label):
                facts, _p, raw, *_r = self._compose_consistent(
                    score_mutations=mutations
                )
                self._refused_reason(
                    lambda f=facts, r=raw: self._run_stages(f, raw=r),
                    processing_module.REASON_SCORE_RESULT,
                )

    def test_expected_parameters_hash_precedence_over_reason13(self) -> None:
        facts, _p, raw, *_r = self._compose_consistent(
            score_mutations={("parameters_hash",): "8" * 64}
        )
        self._refused_reason(
            lambda: self._run_stages(facts, raw=raw),
            processing_module.REASON_SCORING_PARAMS,
        )

    def test_score_key_set_violations_stay_structural_reason3(self) -> None:
        for label, mutations in (
            ("missing_fit_subscore",
             {("fit_subscores", "interest"): self.SCORE_DELETE}),
            ("extra_fit_subscore",
             {("fit_subscores", "ghost_axis"): 0.5}),
            ("extra_top_level_key",
             {("ghost_field",): 1}),
        ):
            with self.subTest(case=label):
                with self.assertRaisesRegex(ValueError, "key set mismatch"):
                    self._compose_consistent(score_mutations=dict(mutations))

    def test_semantic_reason_precedence_chain(self) -> None:
        # 9 over 10: a blank owner description stops the chain first.
        facts, _p, raw, *_r = self._compose_consistent(
            extraction_mutations={("description",): " "},
            alignment_mutations={("matches", 0, "evidence_ids"): ["ev-ghost"]},
        )
        self._refused_reason(
            lambda: processing_module._admit_extraction_stage(facts, raw),
            processing_module.REASON_EXTRACTION,
        )
        # 10 over 11.
        facts, _p, raw, *_r = self._compose_consistent(
            alignment_mutations={("matches", 0, "evidence_ids"): ["ev-ghost"]},
            params_sha_override="9" * 64,
        )
        def probe_ten(f=facts, r=raw):
            admitted = processing_module._admit_extraction_stage(f, r)
            vacancy = admitted.pop("vacancy")
            processing_module._admit_alignment_stage(
                f, self._FakeSnapshot(self), vacancy
            )
        self._refused_reason(probe_ten, processing_module.REASON_ALIGNMENT)
        # 11 over 12.
        facts, _p, raw, *_r = self._compose_consistent(
            params_sha_override="9" * 64,
            policy_sha_override="7" * 64,
        )
        def probe_eleven(f=facts, r=raw):
            admitted = processing_module._admit_extraction_stage(f, r)
            vacancy = admitted.pop("vacancy")
            admitted.update(processing_module._admit_alignment_stage(
                f, self._FakeSnapshot(self), vacancy
            ))
            admitted.pop("accepted_alignment")
            processing_module._admit_parameter_stage(f)
        self._refused_reason(probe_eleven, processing_module.REASON_SCORING_PARAMS)
        # 12 over 13.
        true_score = self._true_score(self._alignment_output())
        facts, _p, raw, *_r = self._compose_consistent(
            policy_sha_override="7" * 64,
            score_mutations={("fit",): float(true_score["fit"]) + 1e-9},
        )
        self._refused_reason(
            lambda f=facts: processing_module._admit_policy_stage(f),
            processing_module.REASON_OPPORTUNITY_POLICY,
        )

    # --------------------------------------------- view + CM wiring units

    class _RecordingLease:
        def __init__(self):
            self.calls = []

        def revalidate_raw(self):
            self.calls.append("raw")

    class _RecordingSnapshot:
        def __init__(self):
            self.calls = []
            self.closed = 0

        def revalidate(self):
            self.calls.append("profile")

        def close(self):
            self.closed += 1

    def _make_view(self, lease=None, snapshot=None):
        return processing_module.SemanticAdmissionView(
            lease or self._RecordingLease(),
            snapshot or self._RecordingSnapshot(),
            raw=self._raw_facts(),
            provisional_detail=None,
            profile_binding_shas=(("profile_sha256", "3" * 64),),
            score_result_bytes=b"abc",
            score_result_sha256="d" * 64,
        )

    def test_view_hides_private_state_and_is_immutable(self) -> None:
        view = self._make_view()
        for hidden in ("_lease", "_snapshot", "_sealed", "snapshot", "lease"):
            self.assertFalse(hasattr(view, hidden))
            with self.assertRaises(AttributeError):
                getattr(view, hidden)
        with self.assertRaises(AttributeError):
            view.raw = None
        with self.assertRaises(AttributeError):
            delattr(view, "score_result_bytes")
        self.assertEqual(view.score_result_bytes, b"abc")
        self.assertIsInstance(view.raw, processing_module.RawSnapshotFacts)
        processing_module._assert_fully_immutable(view.raw, "view.raw")
        self.assertEqual(view.raw.job_key, self.JOB_KEY)

    def test_view_revalidation_is_raw_first_then_profile_and_maps_reasons(self) -> None:
        lease, snapshot = self._RecordingLease(), self._RecordingSnapshot()
        view = self._make_view(lease, snapshot)
        view.revalidate_all()
        self.assertEqual(lease.calls, ["raw"])
        self.assertEqual(snapshot.calls, ["profile"])

        failing = self._RecordingLease()
        failing.revalidate_raw = lambda: (_ for _ in ()).throw(
            processing_module.ProcessingRefused(
                processing_module.REASON_RAW_SNAPSHOT, "drift"
            )
        )
        untouched = self._RecordingSnapshot()
        view = self._make_view(failing, untouched)
        self._refused_reason(
            view.revalidate_all, processing_module.REASON_RAW_SNAPSHOT
        )
        self.assertEqual(untouched.calls, [])

        broken = self._RecordingSnapshot()
        def boom():
            raise ValueError("content drifted under the generation lock")
        broken.revalidate = boom
        view = self._make_view(self._RecordingLease(), broken)
        exc = self._refused_reason(
            view.revalidate_all, processing_module.REASON_PROFILE_EVIDENCE
        )
        self.assertIn("profile", exc.detail)

    def test_view_release_closes_snapshot_exactly_once(self) -> None:
        snapshot = self._RecordingSnapshot()
        view = self._make_view(snapshot=snapshot)
        self.assertFalse(hasattr(view, "_release"))
        with self.assertRaises(AttributeError):
            getattr(view, "_release")
        release = object.__getattribute__(view, "_release")
        release()
        self.assertEqual(snapshot.closed, 1)
        object.__getattribute__(view, "_release")()
        self.assertEqual(snapshot.closed, 1)

    def test_continuation_zero_owner_calls_on_exact_replay_and_reason6(self) -> None:
        calls = {"store": 0, "extract": 0, "align": 0, "score": 0}

        class SpyStore:
            @classmethod
            def open_existing(cls, data_home=None):
                calls["store"] += 1
                raise AssertionError("owner store must not open")

        original_store = processing_module.ProfileStore
        original_open = processing_module.open_current_raw_admission
        original_accepts = (
            processing_module.accept_extraction,
            processing_module.accept_alignment,
            processing_module.deterministic_score,
        )

        def restore():
            processing_module.ProfileStore = original_store
            processing_module.open_current_raw_admission = original_open
            (
                processing_module.accept_extraction,
                processing_module.accept_alignment,
                processing_module.deterministic_score,
            ) = original_accepts

        self.addCleanup(restore)
        processing_module.ProfileStore = SpyStore

        @contextlib.contextmanager
        def exact_replay_stub(*_a, **_k):
            yield processing_module.ReplayClassification(
                processing_module.DISPOSITION_EXACT_REPLAY, b"sealed", "exact"
            )

        processing_module.open_current_raw_admission = exact_replay_stub
        with processing_module.continue_current_semantic_admission(
            pathlib.Path("/unused"), "x.json",
            supplied_operation_id="op-12345678",
            supplied_config_path="/cfg/product.toml",
            supplied_profile_id=self.PROFILE_ID,
            supplied_job_key=self.JOB_KEY,
            supplied_track=self.TRACK,
        ) as got:
            self.assertEqual(got.disposition, "exact_replay")
        self.assertEqual(calls, {"store": 0, "extract": 0, "align": 0, "score": 0})

        @contextlib.contextmanager
        def reason6_stub(*_a, **_k):
            raise processing_module.ProcessingRefused(
                processing_module.REASON_EXISTING_RECEIPT, "changed binding"
            )
            yield None

        processing_module.open_current_raw_admission = reason6_stub
        with self.assertRaises(processing_module.ProcessingRefused) as refused:
            with processing_module.continue_current_semantic_admission(
                pathlib.Path("/unused"), "x.json",
                supplied_operation_id="op-12345678",
                supplied_config_path="/cfg/product.toml",
                supplied_profile_id=self.PROFILE_ID,
                supplied_job_key=self.JOB_KEY,
                supplied_track=self.TRACK,
            ):
                pass
        self.assertEqual(
            refused.exception.reason,
            processing_module.REASON_EXISTING_RECEIPT,
        )
        self.assertEqual(calls, {"store": 0, "extract": 0, "align": 0, "score": 0})

    def test_continuation_enters_owner_path_only_for_continuations(self) -> None:
        marker = RuntimeError("owner store reached")

        class SpyStore:
            @classmethod
            def open_existing(cls, data_home=None):
                raise marker

        original_store = processing_module.ProfileStore
        original_open = processing_module.open_current_raw_admission
        self.addCleanup(setattr, processing_module, "ProfileStore", original_store)
        self.addCleanup(
            setattr, processing_module, "open_current_raw_admission", original_open
        )
        processing_module.ProfileStore = SpyStore

        class FakeLease:
            raw = object()
            facts = object()
            provisional_detail = None

            def revalidate_raw(self):
                return None

        @contextlib.contextmanager
        def continuation_stub(*_a, **_k):
            yield FakeLease()

        processing_module.open_current_raw_admission = continuation_stub
        with self.assertRaises(RuntimeError) as raised:
            with processing_module.continue_current_semantic_admission(
                pathlib.Path("/unused"), "x.json",
                supplied_operation_id="op-12345678",
                supplied_config_path="/cfg/product.toml",
                supplied_profile_id=self.PROFILE_ID,
                supplied_job_key=self.JOB_KEY,
                supplied_track=self.TRACK,
            ):
                pass
        self.assertIs(raised.exception, marker)


class StageDPart3B2SemanticAdmissionTests(StageDPart3B1RawAdmissionTests):
    """Integration reasons 8-13 over a real committed ProfileStore.

    Requires an environment whose descriptor walk may open system ancestors;
    this sandbox denies os.open('/Users'), so these cases are executed
    independently outside it.
    """

    FORBIDDEN_MODULES = (
        "urllib.request", "urllib.parse", "socket", "ssl", "subprocess",
        "http.client", "smtplib", "webbrowser",
    )
    POLICY_SHA = (
        "65b4674413537ca5b151e1c9627585d025aedb3183c70dcae23de9c78e17e13d"
    )

    def _fixture_profile(self):
        from market_aligner.profiler.schema import CandidateProfile, TrackProfile

        return CandidateProfile(
            profile_id=self.GOLDEN.PROFILE_ID,
            version="2024-01",
            tracks={
                "backend": TrackProfile(
                    interest=4,
                    demonstrated_skill=5,
                    confidence=0.9,
                    market_readiness=3,
                    evidence_ids=("ev-1", "ev-2"),
                    rationale="Backend delivery evidence.",
                ),
                "research": TrackProfile(
                    interest=2,
                    demonstrated_skill=2,
                    confidence=0.5,
                    market_readiness=1,
                    evidence_ids=("ev-other",),
                    rationale="Research evidence.",
                ),
            },
        )

    def _fixture_evidence(self):
        from market_aligner.profiler.schema import EvidenceItem

        return [
            EvidenceItem(
                evidence_id="ev-1",
                kind="project",
                claim="Built a deterministic queue service.",
                source_ref="private://portfolio/item-1",
                status="verified",
                confidence=0.9,
            ),
            EvidenceItem(
                evidence_id="ev-2",
                kind="project",
                claim="Owned on-call for the ingest pipeline.",
                source_ref="private://portfolio/item-2",
                status="verified",
                confidence=0.85,
            ),
            EvidenceItem(
                evidence_id="ev-other",
                kind="paper",
                claim="Published queueing analysis.",
                source_ref="private://portfolio/item-3",
                status="verified",
                confidence=0.8,
            ),
        ]

    def _seed_profile_store(self, world):
        from market_aligner.profiler.store import ProfileStore

        store = ProfileStore(str(world["data"]))
        store.save(self._fixture_profile(), self._fixture_evidence())
        return store

    def _apply_true_score(self, payload):
        axes = processing_module.AssessmentAxes(
            technical_alignment=float(
                payload["alignment"]["output"]["technical_alignment"]
            ) * 10,
            evidence_match=float(
                payload["alignment"]["output"]["evidence_match"]
            ) * 10,
            market_demand=0,
            barrier_to_entry=10,
            growth_potential=0,
        )
        result = processing_module.deterministic_score(
            self._fixture_profile(),
            payload["job_key"],
            payload["track"],
            axes,
            processing_module.ScoringParams(),
        )
        payload["scoring"]["expected_score"] = dataclasses.asdict(result)

    def _payload(self, world, main_db, vac_db, *, track="backend"):
        payload = super()._payload(world, main_db, vac_db, track=track)
        self._apply_true_score(payload)
        return payload

    def _profiles_leaf_paths(self, world):
        root = world["data"] / "profiles" / self.GOLDEN.PROFILE_ID
        return [
            root / "generation.json",
            root / "profile.yaml",
            root / "evidence.jsonl",
        ]

    def _prepare(self, *, canonical_store=False):
        from market_aligner.domain.contracts import RawPosting
        from market_aligner.llm.contracts import canonical_hash
        from market_aligner.profiler.store import ProfileStore

        pm = processing_module
        world = self._new_world()
        main_db, vac_db = self._databases(world, canonical_store=canonical_store)
        payload = self._payload(world, main_db, vac_db)
        row = self._seed_posting(world, payload)
        self._seed_profile_store(world)

        # Extraction input bound to the FINAL admitted raw row and the
        # payload raw hashes; output binding already canonical via the
        # fixture receipt builder.
        parsed_raw_json = json.loads(self.RAW_JSON_TEXT)
        extraction_input = {
            "schema_version": pm.EXTRACTION_INPUT_SCHEMA_VERSION,
            "job_key": payload["job_key"],
            "board": row[1],
            "job_id": row[2],
            "url": row[3],
            "fetched_at": row[5],
            "source_content_sha256": payload["raw"]["source_content_sha256"],
            "raw_snapshot_sha256": payload["raw"]["raw_snapshot_sha256"],
            "raw_text": row[6],
            "raw_json": parsed_raw_json,
        }
        payload["extraction"]["receipt"]["input_sha256"] = canonical_hash(
            extraction_input
        )

        # Accepted Vacancy through the canonical owners.
        extraction_owner = pm._extraction_from_structural(
            pm._freeze_structure(payload["extraction"]["output"])
        )
        posting = RawPosting(
            board=row[1],
            job_id=row[2],
            url=row[3],
            fetched_at=row[5],
            raw_text=row[6],
            raw_json=parsed_raw_json,
            content_sha256=payload["raw"]["source_content_sha256"],
        )
        vacancy = pm.accept_extraction(
            posting, extraction_owner, pm.LLMReceipt(**payload["extraction"]["receipt"])
        )

        # Complete committed snapshot context (including the other track)
        # plus the five profile hashes.
        snapshot = ProfileStore(str(world["data"])).coherent_snapshot(
            payload["profile_id"], require_committed_generation=True
        )
        try:
            context = snapshot.context
            payload["profile"] = dict(snapshot.hashes)
        finally:
            snapshot.close()

        alignment_input = {
            "schema_version": pm.ALIGNMENT_INPUT_SCHEMA_VERSION,
            "job_key": payload["job_key"],
            "profile_id": payload["profile_id"],
            "profile_version": payload["profile_version"],
            "track": payload["track"],
            "vacancy": dataclasses.asdict(vacancy),
            "profile_context": context,
            "profile_context_sha256":
                payload["profile"]["profile_context_sha256"],
        }
        payload["alignment"]["receipt"]["input_sha256"] = canonical_hash(
            alignment_input
        )
        name = self._restage(world, payload)
        return {
            "world": world,
            "main_db": main_db,
            "vac_db": vac_db,
            "payload": payload,
            "name": name,
        }

    def _continue(self, prepared, **overrides):
        return processing_module.continue_current_semantic_admission(
            prepared["world"]["data"],
            prepared["name"],
            **{**self._cli(prepared["payload"]), **overrides},
        )

    def _owner_spies(self):
        counts = {"store": 0, "extract": 0, "align": 0, "score": 0}
        originals = {
            "store": processing_module.ProfileStore,
            "extract": processing_module.accept_extraction,
            "align": processing_module.accept_alignment,
            "score": processing_module.deterministic_score,
        }

        class SpyProfileStore:
            @classmethod
            def open_existing(cls, data_home=None):
                counts["store"] += 1
                return originals["store"].open_existing(data_home)

        def spy_extract(*a, **k):
            counts["extract"] += 1
            return originals["extract"](*a, **k)

        def spy_align(*a, **k):
            counts["align"] += 1
            return originals["align"](*a, **k)

        def spy_score(*a, **k):
            counts["score"] += 1
            return originals["score"](*a, **k)

        processing_module.ProfileStore = SpyProfileStore
        processing_module.accept_extraction = spy_extract
        processing_module.accept_alignment = spy_align
        processing_module.deterministic_score = spy_score

        def restore():
            processing_module.ProfileStore = originals["store"]
            processing_module.accept_extraction = originals["extract"]
            processing_module.accept_alignment = originals["align"]
            processing_module.deterministic_score = originals["score"]

        self.addCleanup(restore)
        return counts

    def _rewrite_manifest_state(self, world, state):
        from market_aligner.llm.contracts import canonical_hash

        manifest_path = (
            world["data"]
            / "profiles"
            / self.GOLDEN.PROFILE_ID
            / "generation.json"
        )
        manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
        five = {
            "schema_version": manifest["schema_version"],
            "state": state,
            "profile_id": manifest["profile_id"],
            "profile_file_sha256": manifest["profile_file_sha256"],
            "evidence_file_sha256": manifest["evidence_file_sha256"],
        }
        manifest.update(five)
        manifest["generation_sha256"] = canonical_hash(five)
        manifest_path.write_bytes(
            (processing_module.canonical_json(manifest) + "\n").encode("utf-8")
        )
        os.chmod(manifest_path, 0o600)

    def _rebind_extraction_receipt(self, payload):
        output = payload["extraction"]["output"]
        payload["extraction"]["receipt"]["output_sha256"] = hashlib.sha256(
            processing_module.canonical_json(output).encode("utf-8")
        ).hexdigest()

    def _refused_reason_cm(self, cm_factory, reason):
        with self.assertRaises(processing_module.ProcessingRefused) as refused:
            with cm_factory():
                pass
        self.assertEqual(refused.exception.reason, reason)
        return refused.exception

    # ------------------------------------------------------------ positives

    def test_full_continuation_positive_exposes_immutable_view(self) -> None:
        prepared = self._prepare()
        payload = prepared["payload"]
        output = payload["extraction"]["output"]
        parsed_raw_json = json.loads(self.RAW_JSON_TEXT)
        baseline = _fd_count()
        leaves = self._profiles_leaf_paths(prepared["world"])
        bytes_before = {p: p.read_bytes() for p in leaves}
        modules_before = frozenset(sys.modules)

        with self._continue(prepared) as view:
            self.assertIsInstance(view, processing_module.SemanticAdmissionView)
            for hidden in ("_lease", "_snapshot", "_sealed", "snapshot",
                           "profile", "evidence", "context", "vacancy"):
                self.assertFalse(hasattr(view, hidden))
            for name in (
                "provisional_detail", "profile_binding_shas",
                "extraction_input_sha256", "extraction_output_sha256",
                "extraction_receipt_provenance", "alignment_input_sha256",
                "alignment_output_sha256", "alignment_receipt_provenance",
                "normalized_vacancy_bytes", "normalized_json_sha256",
                "parameters_sha256", "opportunity_policy_sha256",
                "score_result_bytes", "score_result_sha256",
            ):
                self.assertIsInstance(
                    getattr(view, name), (str, bytes, tuple, type(None))
                )
            self.assertIsInstance(view.raw, processing_module.RawSnapshotFacts)
            processing_module._assert_fully_immutable(view.raw, "view.raw")
            with self.assertRaises(dataclasses.FrozenInstanceError):
                view.raw.job_key = "mutated"
            self.assertIsNone(view.provisional_detail)
            view.revalidate_all()

        self.assertEqual(_fd_count(), baseline)
        self.assertEqual({p: p.read_bytes() for p in bytes_before}, bytes_before)
        delta = frozenset(sys.modules) - modules_before
        self.assertEqual(delta & set(self.FORBIDDEN_MODULES), set())

        from market_aligner.llm.contracts import canonical_hash

        expected_input = {
            "schema_version":
                processing_module.EXTRACTION_INPUT_SCHEMA_VERSION,
            "job_key": payload["job_key"],
            "board": self.RAW_BOARD,
            "job_id": self.RAW_JOB_ID,
            "url": self.RAW_URL,
            "fetched_at": self.RECEIPT_T,
            "source_content_sha256": payload["raw"]["source_content_sha256"],
            "raw_snapshot_sha256": payload["raw"]["raw_snapshot_sha256"],
            "raw_text": self.RAW_TEXT,
            "raw_json": json.loads(self.RAW_JSON_TEXT),
        }
        self.assertEqual(
            view.extraction_input_sha256, canonical_hash(expected_input)
        )
        # Whole-profile alignment input: independently rebuild the accepted
        # Vacancy and the complete llm_context (which includes the
        # other-track fact) and bind the exact canonical input hash.
        evidence_map = {
            item.evidence_id: item for item in self._fixture_evidence()
        }
        context = self._fixture_profile().llm_context(evidence_map)
        ledger_ids = [
            row["evidence_id"] for row in context["evidence_ledger"]
        ]
        self.assertIn("ev-other", ledger_ids)
        from market_aligner.domain.contracts import RawPosting

        posting = RawPosting(
            board=self.RAW_BOARD,
            job_id=self.RAW_JOB_ID,
            url=self.RAW_URL,
            fetched_at=self.RECEIPT_T,
            raw_text=self.RAW_TEXT,
            raw_json=parsed_raw_json,
            content_sha256=payload["raw"]["source_content_sha256"],
        )
        extraction_owner = processing_module._extraction_from_structural(
            processing_module._freeze_structure(output)
        )
        receipt_owner = processing_module.LLMReceipt(
            **payload["extraction"]["receipt"]
        )
        vacancy_expected = processing_module.accept_extraction(
            posting, extraction_owner, receipt_owner
        )
        expected_alignment_input = {
            "schema_version":
                processing_module.ALIGNMENT_INPUT_SCHEMA_VERSION,
            "job_key": payload["job_key"],
            "profile_id": payload["profile_id"],
            "profile_version": payload["profile_version"],
            "track": payload["track"],
            "vacancy": dataclasses.asdict(vacancy_expected),
            "profile_context": context,
            "profile_context_sha256": canonical_hash(context),
        }
        self.assertEqual(
            view.alignment_input_sha256,
            canonical_hash(expected_alignment_input),
        )
        self.assertEqual(
            view.profile_binding_shas,
            tuple(sorted(payload["profile"].items())),
        )
        normalized = json.loads(view.normalized_vacancy_bytes.decode("utf-8"))
        output = payload["extraction"]["output"]
        self.assertEqual(normalized["title"], output["title"])
        self.assertEqual(
            normalized["extra"]["unknown_fields"], output["unknown_fields"]
        )
        self.assertNotIn(b"\n", view.normalized_vacancy_bytes[-1:])
        self.assertEqual(
            view.score_result_bytes,
            processing_module.canonical_json(
                payload["scoring"]["expected_score"]
            ).encode("utf-8"),
        )
        self.assertEqual(
            hashlib.sha256(view.score_result_bytes).hexdigest(),
            view.score_result_sha256,
        )
        self.assertEqual(
            view.parameters_sha256,
            processing_module.ScoringParams().parameters_hash,
        )
        self.assertEqual(view.opportunity_policy_sha256, self.POLICY_SHA)
        receipt = payload["extraction"]["receipt"]
        self.assertEqual(
            view.extraction_receipt_provenance,
            (
                receipt["receipt_id"],
                receipt["model"],
                receipt["prompt_version"],
                receipt["created_at"],
            ),
        )

    def test_provisional_retained_continuation_completes_semantics(self) -> None:
        prepared = self._prepare(canonical_store=True)
        sealed = self._seed_exact(prepared["world"], prepared["payload"])
        mutable = bytearray(sealed)
        mutable[-20] ^= 0x01
        self._update_main(
            prepared["world"],
            "UPDATE processing_receipts SET receipt_bytes=?",
            *(bytes(mutable),),
        )
        prepared["name"] = self._restage(prepared["world"], prepared["payload"])
        with self._continue(prepared) as view:
            self.assertIn("independent validation", view.provisional_detail)
            self.assertTrue(view.score_result_sha256)

    # ------------------------------------------------- terminal zero-calls

    def test_exact_replay_runs_zero_semantic_owner_calls(self) -> None:
        prepared = self._prepare(canonical_store=True)
        sealed = self._seed_exact(prepared["world"], prepared["payload"])
        prepared["name"] = self._restage(prepared["world"], prepared["payload"])
        counts = self._owner_spies()
        with self._continue(prepared) as classification:
            self.assertIsInstance(
                classification, processing_module.ReplayClassification
            )
            self.assertEqual(classification.stored_receipt_bytes, sealed)
        self.assertEqual(counts, {"store": 0, "extract": 0, "align": 0, "score": 0})

    def test_reason6_runs_zero_semantic_owner_calls(self) -> None:
        prepared = self._prepare(canonical_store=True)
        world = prepared["world"]
        other_payload = self._payload(world, prepared["main_db"], prepared["vac_db"])
        # Original sealed receipt stored under the same operation id; the
        # staged prepared envelope carries a different binding -> reason 6
        # with zero semantic-owner calls.
        self._seed_exact(world, other_payload)
        counts = self._owner_spies()
        self._refused_reason_cm(
            lambda: self._continue(prepared),
            processing_module.REASON_EXISTING_RECEIPT,
        )
        self.assertEqual(counts, {"store": 0, "extract": 0, "align": 0, "score": 0})

    # ------------------------------------------------------ reason 8 gates

    def test_generation_negatives_map_to_reason8_with_precedence(self) -> None:
        PROFILE_HASH_KEYS = (
            "profile_file_sha256",
            "evidence_file_sha256",
            "profile_sha256",
            "evidence_ledger_sha256",
            "profile_context_sha256",
        )

        def blank_description(payload):
            payload["extraction"]["output"]["description"] = "   "
            self._rebind_extraction_receipt(payload)

        cases = {
            "profiles_root_absent": lambda p: shutil.rmtree(
                p["world"]["data"] / "profiles"
            ),
            "manifest_absent_legacy_unsealed": lambda p: (
                (p["world"]["data"] / "profiles" / self.GOLDEN.PROFILE_ID
                 / "generation.json").unlink()
            ),
            "manifest_in_progress": lambda p: self._rewrite_manifest_state(
                p["world"], "in_progress"
            ),
            "manifest_malformed_bytes": lambda p: (
                (p["world"]["data"] / "profiles" / self.GOLDEN.PROFILE_ID
                 / "generation.json").write_bytes(b"{oops not canonical")
            ),
            "committed_manifest_leaf_hash_mismatch": lambda p: (
                (p["world"]["data"] / "profiles" / self.GOLDEN.PROFILE_ID
                 / "profile.yaml").write_bytes(
                     (p["world"]["data"] / "profiles"
                      / self.GOLDEN.PROFILE_ID / "profile.yaml").read_bytes()
                     + b"# drifted\n")
            ),
            "wrong_profile_version": lambda p: (
                p["payload"].__setitem__("profile_version", "2023-12"),
                p["payload"]["alignment"]["output"].__setitem__(
                    "profile_version", "2023-12"),
                p["payload"]["alignment"]["receipt"].__setitem__(
                    "output_sha256", hashlib.sha256(processing_module
                        .canonical_json(p["payload"]["alignment"]["output"])
                        .encode("utf-8")).hexdigest()),
                p.__setitem__("name", self._restage(p["world"], p["payload"])),
            ),
            "missing_selected_track": lambda p: (
                p["payload"].__setitem__("track", "frontend"),
                p["payload"]["scoring"]["expected_score"].__setitem__(
                    "track", "frontend"),
                p.__setitem__("name", self._restage(p["world"], p["payload"])),
            ),
        }
        for index, hash_key in enumerate(PROFILE_HASH_KEYS):
            cases[f"profile_binding_hash_{hash_key}"] = (
                lambda p, key=hash_key, digit=str(index + 1): (
                    p["payload"]["profile"].__setitem__(key, digit * 64),
                    p.__setitem__(
                        "name", self._restage(p["world"], p["payload"])
                    ),
                )
            )
        for label, mutate in cases.items():
            with self.subTest(case=label):
                prepared = self._prepare()
                mutate(prepared)
                self._refused_reason_cm(
                    lambda pr=prepared: self._continue(pr),
                    processing_module.REASON_PROFILE_EVIDENCE,
                )
        # Reason 8 precedes reason 9.
        prepared = self._prepare()
        blank_description(prepared["payload"])
        prepared["name"] = self._restage(prepared["world"], prepared["payload"])
        shutil.rmtree(prepared["world"]["data"] / "profiles")
        self._refused_reason_cm(
            lambda: self._continue(prepared),
            processing_module.REASON_PROFILE_EVIDENCE,
        )

    # --------------------------------------------- reasons 9-13 negatives

    def test_reason9_to_13_integration_negatives_in_order(self) -> None:
        # 9: owner-invalid prose passes r3 and refuses at the constructor.
        prepared = self._prepare()
        payload = prepared["payload"]
        payload["extraction"]["output"]["description"] = "   "
        self._rebind_extraction_receipt(payload)
        prepared["name"] = self._restage(prepared["world"], payload)
        exc = self._refused_reason_cm(
            lambda: self._continue(prepared), processing_module.REASON_EXTRACTION
        )
        self.assertIn("description are required", exc.detail)

        # 10: other-track citation escape.
        prepared = self._prepare()
        payload = prepared["payload"]
        matches = payload["alignment"]["output"]["matches"]
        matches[0]["evidence_ids"] = ["ev-other"]
        payload["alignment"]["receipt"]["output_sha256"] = hashlib.sha256(
            processing_module.canonical_json(
                payload["alignment"]["output"]
            ).encode("utf-8")
        ).hexdigest()
        prepared["name"] = self._restage(prepared["world"], payload)
        self._refused_reason_cm(
            lambda: self._continue(prepared), processing_module.REASON_ALIGNMENT
        )

        # 11: staged parameters differ from the sole object.
        prepared = self._prepare()
        payload = prepared["payload"]
        payload["scoring"]["parameters_sha256"] = "9" * 64
        prepared["name"] = self._restage(prepared["world"], payload)
        self._refused_reason_cm(
            lambda: self._continue(prepared),
            processing_module.REASON_SCORING_PARAMS,
        )

        # 12: policy substitution.
        prepared = self._prepare()
        payload = prepared["payload"]
        payload["scoring"]["opportunity_policy_sha256"] = "7" * 64
        prepared["name"] = self._restage(prepared["world"], payload)
        self._refused_reason_cm(
            lambda: self._continue(prepared),
            processing_module.REASON_OPPORTUNITY_POLICY,
        )

        # 13: exact-value drift and isolated int-vs-float identity.
        for label, mutate in (
            ("fit_delta", lambda s: s.__setitem__("fit",
                                                  float(s["fit"]) + 1e-9)),
            ("fit_status_swap", lambda s: s.__setitem__("fit_status",
                                                        "calibrated")),
            ("market_demand_int_zero", lambda s: s["opportunity_subscores"]
                .__setitem__("market_demand", 0)),
        ):
            with self.subTest(case=label):
                prepared = self._prepare()
                mutate(prepared["payload"]["scoring"]["expected_score"])
                prepared["name"] = self._restage(
                    prepared["world"], prepared["payload"]
                )
                self._refused_reason_cm(
                    lambda pr=prepared: self._continue(pr),
                    processing_module.REASON_SCORE_RESULT,
                )

    # ------------------------------------------------- provenance truth

    def test_imported_provenance_substitutions_recorded_not_authenticated(self) -> None:
        from market_aligner.domain.contracts import RawPosting
        from market_aligner.llm.contracts import canonical_hash

        prepared = self._prepare()
        payload = prepared["payload"]
        receipt = payload["extraction"]["receipt"]
        substituted = {
            "receipt_id": "rcpt-imported-9",
            "model": "imported-model",
            "prompt_version": "imported-pv",
            "created_at": "2026-08-24T09:30:00.000000Z",
        }
        receipt.update(substituted)
        # receipt_id flows into the accepted Vacancy, so the downstream
        # alignment input must be rehashed over the NEWLY accepted vacancy
        # plus the exact complete profile context before restaging.
        parsed_raw_json = json.loads(self.RAW_JSON_TEXT)
        posting = RawPosting(
            board=self.RAW_BOARD,
            job_id=self.RAW_JOB_ID,
            url=self.RAW_URL,
            fetched_at=self.RECEIPT_T,
            raw_text=self.RAW_TEXT,
            raw_json=parsed_raw_json,
            content_sha256=payload["raw"]["source_content_sha256"],
        )
        extraction_owner = processing_module._extraction_from_structural(
            processing_module._freeze_structure(payload["extraction"]["output"])
        )
        vacancy = processing_module.accept_extraction(
            posting,
            extraction_owner,
            processing_module.LLMReceipt(**payload["extraction"]["receipt"]),
        )
        evidence_map = {
            item.evidence_id: item for item in self._fixture_evidence()
        }
        context = self._fixture_profile().llm_context(evidence_map)
        payload["alignment"]["receipt"]["input_sha256"] = canonical_hash(
            {
                "schema_version":
                    processing_module.ALIGNMENT_INPUT_SCHEMA_VERSION,
                "job_key": payload["job_key"],
                "profile_id": payload["profile_id"],
                "profile_version": payload["profile_version"],
                "track": payload["track"],
                "vacancy": dataclasses.asdict(vacancy),
                "profile_context": context,
                "profile_context_sha256": canonical_hash(context),
            }
        )
        prepared["name"] = self._restage(prepared["world"], payload)
        with self._continue(prepared) as view:
            self.assertEqual(
                view.extraction_receipt_provenance,
                (
                    substituted["receipt_id"],
                    substituted["model"],
                    substituted["prompt_version"],
                    substituted["created_at"],
                ),
            )
            alignment_receipt = payload["alignment"]["receipt"]
            self.assertEqual(
                view.alignment_receipt_provenance,
                (
                    alignment_receipt["receipt_id"],
                    alignment_receipt["model"],
                    alignment_receipt["prompt_version"],
                    alignment_receipt["created_at"],
                ),
            )

    def test_unrehashed_created_at_corruption_stays_reason3(self) -> None:
        prepared = self._prepare()
        # A VALID envelope is staged first; corrupt its exact retained bytes
        # in place with no filename/file-hash rebinding.
        leaf = (
            prepared["world"]["data"] / "state" / "processing-inbox"
            / prepared["name"]
        )
        raw_bytes = bytearray(leaf.read_bytes())
        raw_bytes[-64] ^= 0x01
        leaf.write_bytes(bytes(raw_bytes))
        os.chmod(leaf, 0o600)
        exc = self._refused(
            lambda: processing_module.run_read_only_replay(
                prepared["world"]["data"], prepared["name"],
                **self._cli(prepared["payload"]),
            ),
            processing_module.REASON_ENVELOPE_BYTES,
        )
        self.assertTrue(exc.detail)

    def test_same_operation_changed_binding_remains_reason6(self) -> None:
        # The ORIGINAL sealed receipt (from _seed_exact) stays stored and
        # untouched; only the rehashed changed envelope is staged under the
        # SAME operation id, so the stored binding differs -> reason 6.
        prepared = self._prepare(canonical_store=True)
        world = prepared["world"]
        other_payload = self._payload(world, prepared["main_db"], prepared["vac_db"])
        sealed = self._seed_exact(world, other_payload)
        changed = copy.deepcopy(other_payload)
        changed.pop("_staged_name", None)
        changed["extraction"]["receipt"]["model"] = "changed-model"
        prepared["name"] = self._stage(world, changed)
        prepared["payload"] = changed
        counts = self._owner_spies()
        self._refused_reason_cm(
            lambda: self._continue(prepared),
            processing_module.REASON_EXISTING_RECEIPT,
        )
        self.assertIsNotNone(sealed)
        self.assertEqual(counts["store"], 0)

    # ------------------------------------------- drift / cleanup / no-writes

    def test_post_success_drift_maps_raw_and_profile_and_restores(self) -> None:
        prepared = self._prepare()
        profile_leaf = (
            prepared["world"]["data"] / "profiles" / self.GOLDEN.PROFILE_ID
            / "profile.yaml"
        )
        original_bytes = profile_leaf.read_bytes()
        baseline = _fd_count()
        try:
            with self._continue(prepared) as view:
                profile_leaf.write_bytes(original_bytes + b"# drifted\n")
                self._refused_reason_cm(
                    lambda: view.revalidate_all(),
                    processing_module.REASON_PROFILE_EVIDENCE,
                )
                profile_leaf.write_bytes(original_bytes)
                self.assertIsNone(view.revalidate_all())
                self._update_row(
                    prepared["world"],
                    "UPDATE postings SET fetched_at=?",
                    *("2026-08-25T23:59:59.000000Z",),
                )
                exc = self._refused_reason_cm(
                    lambda: view.revalidate_all(),
                    processing_module.REASON_RAW_SNAPSHOT,
                )
                self.assertIn("raw snapshot", str(exc))
        finally:
            profile_leaf.write_bytes(original_bytes)
            os.chmod(profile_leaf, 0o600)
        self.assertEqual(_fd_count(), baseline)

    def test_continuation_performs_no_ddl_dml_on_databases(self) -> None:
        prepared = self._prepare()
        WRITE_ACTIONS = [
            name for name in (
                "SQLITE_DELETE", "SQLITE_INSERT", "SQLITE_UPDATE",
                "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE",
                "SQLITE_CREATE_TEMP_INDEX", "SQLITE_CREATE_TEMP_TABLE",
                "SQLITE_CREATE_TEMP_TRIGGER", "SQLITE_CREATE_TRIGGER",
                "SQLITE_CREATE_VIEW", "SQLITE_DROP_INDEX", "SQLITE_DROP_TABLE",
                "SQLITE_DROP_TEMP_INDEX", "SQLITE_DROP_TEMP_TABLE",
                "SQLITE_DROP_TEMP_TRIGGER", "SQLITE_DROP_TRIGGER",
                "SQLITE_DROP_VIEW", "SQLITE_ALTER_TABLE", "SQLITE_REINDEX",
                "SQLITE_SAVEPOINT", "SQLITE_TRANSACTION",
            )
            if hasattr(sqlite3, name)
        ]
        write_codes = {
            getattr(sqlite3, name): name.split("SQLITE_")[1]
            for name in WRITE_ACTIONS
        }
        attempted_writes = []
        allowed_pragmas = {
            "query_only", "database_list", "index_list", "index_info",
            "foreign_key_list", "busy_timeout",
        }

        def authorizer(action, arg1, _arg2, _db, _source):
            if action in write_codes:
                attempted_writes.append(write_codes[action])
                return sqlite3.SQLITE_DENY
            if action == getattr(sqlite3, "SQLITE_PRAGMA", 19):
                if str(arg1).lower() in allowed_pragmas:
                    return sqlite3.SQLITE_OK
                attempted_writes.append(f"PRAGMA {arg1}")
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        original_connect = sqlite3.connect

        def armed_connect(*args, **kwargs):
            conn = original_connect(*args, **kwargs)
            try:
                conn.set_authorizer(authorizer)
            except Exception:
                pass
            return conn

        with contextlib.closing(original_connect(prepared["main_db"])) as conn:
            main_before = list(conn.iterdump())
        with contextlib.closing(original_connect(prepared["vac_db"])) as conn:
            vac_before = list(conn.iterdump())
        leaves = self._profiles_leaf_paths(prepared["world"])
        bytes_before = {p: p.read_bytes() for p in leaves}

        self.addCleanup(setattr, sqlite3, "connect", original_connect)
        sqlite3.connect = armed_connect
        with self._continue(prepared) as view:
            view.revalidate_all()
        sqlite3.connect = original_connect

        self.assertEqual(attempted_writes, [])
        with contextlib.closing(original_connect(prepared["main_db"])) as conn:
            self.assertEqual(list(conn.iterdump()), main_before)
        with contextlib.closing(original_connect(prepared["vac_db"])) as conn:
            self.assertEqual(list(conn.iterdump()), vac_before)
        self.assertEqual({p: p.read_bytes() for p in bytes_before}, bytes_before)

    def test_external_provider_seams_explode_zero(self) -> None:
        counters: dict[str, int] = {}

        def bump(key):
            counters[key] = counters.get(key, 0) + 1
            raise AssertionError(f"forbidden seam invoked: {key}")

        def arm(module, attr, key):
            if module is None or not hasattr(module, attr):
                return None
            original = getattr(module, attr)

            def bomb(*args, **kwargs):
                bump(key)

            setattr(module, attr, bomb)
            return (module, attr, original)

        import smtplib
        import socket
        import subprocess as subprocess_module
        import urllib.request
        import webbrowser

        from market_aligner.applications import contracts as applications_contracts
        from market_aligner.collectors import engine as collector_engine
        from market_aligner.research import store as research_store

        armed = [
            arm(subprocess_module, "Popen", "subprocess.Popen"),
            arm(subprocess_module, "run", "subprocess.run"),
            arm(socket, "create_connection", "socket.create_connection"),
            arm(urllib.request, "urlopen", "urllib.request.urlopen"),
            arm(smtplib, "SMTP", "smtplib.SMTP"),
            arm(webbrowser, "open", "webbrowser.open"),
            arm(collector_engine.Collector, "discover", "collector.discover"),
            arm(collector_engine.Collector, "fetch", "collector.fetch"),
            arm(research_store.AssessmentStore, "upsert_score",
                "research.upsert_score"),
            arm(applications_contracts.JAAClient, "create_application",
                "jaa.create_application")
            if hasattr(applications_contracts, "JAAClient") else None,
        ]

        def restore():
            for entry in armed:
                if entry is None:
                    continue
                module, attr, original = entry
                setattr(module, attr, original)

        self.addCleanup(restore)
        prepared = self._prepare()
        with self._continue(prepared) as view:
            self.assertTrue(view.score_result_sha256)
        self.assertEqual(counters, {})

    # ------------------------------------------------------- process-one C2

    def _prepare_process_one(self):
        from market_aligner.research.store import AssessmentStore
        from market_aligner.state.vacancies import JobDatabase

        prepared = self._prepare(canonical_store=False)
        AssessmentStore(prepared["main_db"])
        JobDatabase(prepared["vac_db"])
        os.chmod(prepared["main_db"], 0o600)
        os.chmod(prepared["vac_db"], 0o600)
        return prepared

    def _process_one(self, prepared):
        return processing_module.process_one(
            prepared["world"]["data"],
            prepared["name"],
            **self._cli(prepared["payload"]),
        )

    def _logical_process_counts(self, prepared):
        with contextlib.closing(sqlite3.connect(prepared["main_db"])) as main:
            tables = {
                row[0]
                for row in main.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            return {
                "receipts": (
                    main.execute(
                        "SELECT COUNT(*) FROM processing_receipts"
                    ).fetchone()[0]
                    if "processing_receipts" in tables
                    else 0
                ),
                "assessments": main.execute(
                    "SELECT COUNT(*) FROM assessments"
                ).fetchone()[0],
                "events": main.execute(
                    "SELECT COUNT(*) FROM assessment_events"
                ).fetchone()[0],
            }

    def test_process_one_creates_once_then_replays_exact_without_profile(self):
        pm = processing_module
        prepared = self._prepare_process_one()
        baseline = _fd_count()
        traced: list[str] = []
        original_open = pm._open_read_view

        def traced_open(*args, **kwargs):
            connection = original_open(*args, **kwargs)
            connection.set_trace_callback(traced.append)
            return connection

        pm._open_read_view = traced_open
        self.addCleanup(setattr, pm, "_open_read_view", original_open)
        created = self._process_one(prepared)
        self.assertTrue(created.endswith(b"\n"))
        receipt = pm.parse_processing_receipt(created)
        self.assertEqual(receipt["operation_id"], prepared["payload"]["operation_id"])
        self.assertEqual(receipt["created_at"], receipt["assessment_event"]["created_at"])
        self.assertEqual(self._logical_process_counts(prepared), {
            "receipts": 1, "assessments": 1, "events": 1,
        })
        with contextlib.closing(sqlite3.connect(prepared["vac_db"])) as vacancy:
            normalized = vacancy.execute(
                "SELECT normalized_json,normalized_at FROM normalised_jobs"
            ).fetchall()
        self.assertEqual(len(normalized), 1)
        self.assertEqual(
            hashlib.sha256(normalized[0][0].encode("utf-8")).hexdigest(),
            receipt["normalised_projection"]["normalized_json_sha256"],
        )
        self.assertEqual(
            normalized[0][1], receipt["normalised_projection"]["normalized_at"]
        )
        self.assertFalse(
            any(statement.lstrip().upper().startswith("UPDATE ") for statement in traced)
        )

        profile_directory = (
            prepared["world"]["data"]
            / "profiles"
            / prepared["payload"]["profile_id"]
        )
        os.rename(profile_directory, profile_directory.with_name("profile-removed"))
        replayed = self._process_one(prepared)
        self.assertEqual(replayed, created)
        self.assertEqual(self._logical_process_counts(prepared), {
            "receipts": 1, "assessments": 1, "events": 1,
        })
        self.assertEqual(_fd_count(), baseline)

    def test_public_cli_writes_creation_and_replay_receipt_bytes_unchanged(self):
        import argparse
        import io

        from market_aligner import cli as cli_module

        prepared = self._prepare_process_one()
        args = argparse.Namespace(
            data_home=prepared["world"]["data"],
            processing_envelope=prepared["name"],
            operation_id=prepared["payload"]["operation_id"],
            config=pathlib.Path(prepared["payload"]["config"]["source_path"]),
            profile_id=prepared["payload"]["profile_id"],
            job_key=prepared["payload"]["job_key"],
            track=prepared["payload"]["track"],
        )
        created_out = io.BytesIO()
        created_err = io.StringIO()
        self.assertEqual(
            cli_module._process_one_command(
                args, out=created_out, err=created_err
            ),
            0,
        )
        self.assertEqual(created_err.getvalue(), "")
        with contextlib.closing(
            sqlite3.connect(prepared["main_db"])
        ) as connection:
            stored = connection.execute(
                "SELECT receipt_bytes FROM processing_receipts"
            ).fetchone()[0]
        self.assertEqual(created_out.getvalue(), stored)

        replay_out = io.BytesIO()
        replay_err = io.StringIO()
        self.assertEqual(
            cli_module._process_one_command(
                args, out=replay_out, err=replay_err
            ),
            0,
        )
        self.assertEqual(replay_err.getvalue(), "")
        self.assertEqual(replay_out.getvalue(), stored)

    def test_public_cli_emits_one_canonical_refusal_and_retains_valid_operation(self):
        import argparse
        import io

        from market_aligner import cli as cli_module

        prepared = self._prepare_process_one()
        base = dict(
            data_home=prepared["world"]["data"],
            processing_envelope=prepared["name"],
            config=pathlib.Path(prepared["payload"]["config"]["source_path"]),
            profile_id=prepared["payload"]["profile_id"],
            job_key=prepared["payload"]["job_key"],
            track=prepared["payload"]["track"],
        )
        cases = (
            (
                argparse.Namespace(operation_id="bad", **base),
                processing_module.REASON_OPERATION_ID,
                False,
            ),
            (
                argparse.Namespace(
                    operation_id=prepared["payload"]["operation_id"],
                    **{**base, "track": "different"},
                ),
                processing_module.REASON_CLI_IDENTITY,
                True,
            ),
        )
        for args, reason, has_operation in cases:
            with self.subTest(reason=reason):
                output = io.BytesIO()
                errors = io.StringIO()
                self.assertEqual(
                    cli_module._process_one_command(
                        args, out=output, err=errors
                    ),
                    2,
                )
                self.assertEqual(output.getvalue(), b"")
                line = errors.getvalue()
                self.assertTrue(line.endswith("\n"))
                self.assertEqual(line.count("\n"), 1)
                parsed = processing_module.strict_json_loads(
                    line.encode("utf-8")
                )
                self.assertEqual(
                    set(parsed),
                    {
                        "command",
                        "status",
                        "reason",
                        "detail",
                    }
                    | ({"operation_id"} if has_operation else set()),
                )
                self.assertEqual(parsed["command"], "process-one")
                self.assertEqual(parsed["status"], "refused")
                self.assertEqual(parsed["reason"], reason)
                if has_operation:
                    self.assertEqual(
                        parsed["operation_id"], args.operation_id
                    )

    def test_process_one_parser_exposes_only_the_contracted_public_inputs(self):
        from market_aligner import cli as cli_module

        parser = cli_module.build_parser()
        args = parser.parse_args(
            [
                "process-one",
                "--operation-id",
                "operation-001",
                "--config",
                "/private/config.yaml",
                "--profile-id",
                self.GOLDEN.PROFILE_ID,
                "--job-key",
                "fixture:one",
                "--track",
                "backend",
                "--processing-envelope",
                "a" * 64 + ".json",
                "--data-home",
                "/private/data",
            ]
        )
        self.assertEqual(args.command, "process-one")
        self.assertEqual(
            set(vars(args)),
            {
                "command",
                "operation_id",
                "config",
                "profile_id",
                "job_key",
                "track",
                "processing_envelope",
                "data_home",
                "handler",
            },
        )
        self.assertIs(args.handler, cli_module._process_one_command)

    def test_process_one_faults_roll_back_both_databases_then_retry(self):
        pm = processing_module
        for boundary in (
            "after_process_one_transaction_recheck",
            "after_process_one_begin",
            "after_migration_apply",
            "after_normalized_cas",
            "after_assessment_cas",
            "after_event_insert",
            "after_receipt_insert",
            "after_transaction_reread",
            "before_process_one_commit",
        ):
            with self.subTest(boundary=boundary):
                prepared = self._prepare_process_one()
                pm.install_fault(boundary, RuntimeError(boundary))
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    self._process_one(prepared)
                self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
                self.assertIn(boundary, caught.exception.detail)
                pm.clear_faults()
                self.assertEqual(self._logical_process_counts(prepared), {
                    "receipts": 0, "assessments": 0, "events": 0,
                })
                with contextlib.closing(
                    sqlite3.connect(prepared["vac_db"])
                ) as vacancy:
                    self.assertEqual(
                        vacancy.execute(
                            "SELECT COUNT(*) FROM normalised_jobs"
                        ).fetchone()[0],
                        0,
                    )
                self.assertTrue(self._process_one(prepared).endswith(b"\n"))

    def test_process_one_post_commit_fault_recovers_exact_success(self):
        pm = processing_module
        prepared = self._prepare_process_one()
        pm.install_fault(
            "after_process_one_commit", RuntimeError("stdout-boundary")
        )
        try:
            recovered = self._process_one(prepared)
        finally:
            pm.clear_faults()
        with contextlib.closing(
            sqlite3.connect(prepared["main_db"])
        ) as connection:
            stored = connection.execute(
                "SELECT receipt_bytes FROM processing_receipts"
            ).fetchone()[0]
        self.assertEqual(recovered, stored)
        self.assertEqual(
            self._logical_process_counts(prepared),
            {"receipts": 1, "assessments": 1, "events": 1},
        )
        self.assertEqual(self._process_one(prepared), stored)

    def test_transaction_storage_and_interruption_errors_map_after_empty_recovery(self):
        pm = processing_module
        cases = (
            (sqlite3.OperationalError("busy"), sqlite3.SQLITE_BUSY, pm.REASON_ATOMIC_BUSY),
            (sqlite3.OperationalError("locked"), sqlite3.SQLITE_LOCKED, pm.REASON_ATOMIC_BUSY),
            (sqlite3.OperationalError("full"), sqlite3.SQLITE_FULL, pm.REASON_STORAGE_FULL),
            (sqlite3.OperationalError("io"), sqlite3.SQLITE_IOERR_WRITE, pm.REASON_STORAGE_IO_ERROR),
            (sqlite3.OperationalError("interrupt"), sqlite3.SQLITE_INTERRUPT, pm.REASON_INTERRUPTED),
            (KeyboardInterrupt(), None, pm.REASON_INTERRUPTED),
        )
        for injected, code, reason in cases:
            with self.subTest(reason=reason, code=code):
                prepared = self._prepare_process_one()
                if code is not None:
                    injected.sqlite_errorcode = code
                    injected.sqlite_errorname = "INJECTED"
                pm.install_fault("before_process_one_commit", injected)
                try:
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        self._process_one(prepared)
                finally:
                    pm.clear_faults()
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(
                    self._logical_process_counts(prepared),
                    {"receipts": 0, "assessments": 0, "events": 0},
                )
                self.assertTrue(self._process_one(prepared).endswith(b"\n"))

    def test_public_process_one_never_converts_incoherent_recovery_to_success(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare_process_one()
        pm.install_fault("before_process_one_commit", RuntimeError("caught"))
        incoherent = pm.RecoveredTransactionClassification(
            pm.RECOVERY_DURABLE_INCOHERENT,
            None,
            "injected partial graph",
        )
        try:
            with mock.patch.object(
                pm,
                "recover_process_one_durable_truth",
                return_value=incoherent,
            ):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    self._process_one(prepared)
        finally:
            pm.clear_faults()
        self.assertEqual(
            caught.exception.reason, pm.REASON_RECOVERY_INCOHERENT
        )
        self.assertIn("partial", caught.exception.detail)

    def test_killed_child_reopens_journal_and_reaches_one_exact_outcome(self):
        pm = processing_module
        child = r'''
import json
import os
import pathlib
import sys
from market_aligner import processing as pm

invocation = json.loads(sys.argv[1])
target = sys.argv[2]
original = pm._maybe_fault
def crash(boundary):
    if boundary == target:
        os._exit(91)
    return original(boundary)
pm._maybe_fault = crash
pm.process_one(
    pathlib.Path(invocation["data_home"]),
    invocation["envelope_name"],
    **invocation["cli"],
)
'''
        for boundary in (
            "after_process_one_begin",
            "after_migration_apply",
            "after_normalized_cas",
            "after_assessment_cas",
            "after_event_insert",
            "after_receipt_insert",
            "after_transaction_reread",
            "before_process_one_commit",
            "after_process_one_commit",
        ):
            with self.subTest(boundary=boundary):
                prepared = self._prepare_process_one()
                invocation = {
                    "data_home": str(prepared["world"]["data"]),
                    "envelope_name": prepared["name"],
                    "cli": self._cli(prepared["payload"]),
                }
                environment = os.environ.copy()
                environment["PYTHONPATH"] = SRC
                run = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        child,
                        json.dumps(invocation, sort_keys=True),
                        boundary,
                    ],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(run.returncode, 91, run.stderr.decode())
                if boundary not in (
                    "after_process_one_begin",
                    "after_process_one_commit",
                ):
                    journals = list(
                        prepared["world"]["data"].rglob("*.sqlite3-journal")
                    )
                    self.assertTrue(journals)
                recovered = self._process_one(prepared)
                receipt = pm.parse_processing_receipt(recovered)
                self.assertEqual(
                    receipt["operation_id"], prepared["payload"]["operation_id"]
                )
                self.assertEqual(
                    self._logical_process_counts(prepared),
                    {"receipts": 1, "assessments": 1, "events": 1},
                )
                with contextlib.closing(
                    sqlite3.connect(prepared["vac_db"])
                ) as vacancy:
                    self.assertEqual(
                        vacancy.execute(
                            "SELECT COUNT(*) FROM normalised_jobs"
                        ).fetchone()[0],
                        1,
                    )
                self.assertEqual(self._process_one(prepared), recovered)

    def test_kill_during_observed_attached_commit_recovers_exactly(self):
        """SIGKILL only after SQLite exposes the live master journal.

        The ordinary boundary campaign proves the application-visible
        transaction stages.  This stress probe covers the distinct internal
        SQLite boundary required by the contract: the child is released from
        the last pre-COMMIT hook, the parent observes the attached-database
        master journal, and only then kills the child.  Failure to observe the
        state is a failure rather than a silent pass.
        """

        child = r'''
import json
import os
import pathlib
import sys
import time
from market_aligner import processing as pm

invocation = json.loads(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
release = pathlib.Path(sys.argv[3])
original = pm._maybe_fault
def rendezvous(boundary):
    if boundary == "before_process_one_commit":
        ready.write_bytes(b"ready\n")
        while not release.exists():
            time.sleep(0.0001)
    return original(boundary)
pm._maybe_fault = rendezvous
pm.process_one(
    pathlib.Path(invocation["data_home"]),
    invocation["envelope_name"],
    **invocation["cli"],
)
'''
        observed = False
        attempts = 24
        for attempt in range(attempts):
            prepared = self._prepare_process_one()
            payload = prepared["payload"]
            payload["alignment"]["output"]["unknowns"] = [
                f"unknown-{index:03d}-" + "x" * 3980
                for index in range(256)
            ]
            payload["alignment"]["receipt"]["output_sha256"] = hashlib.sha256(
                processing_module.canonical_json(
                    payload["alignment"]["output"]
                ).encode("utf-8")
            ).hexdigest()
            prepared["name"] = self._restage(prepared["world"], payload)
            invocation = {
                "data_home": str(prepared["world"]["data"]),
                "envelope_name": prepared["name"],
                "cli": self._cli(payload),
            }
            marker_root = prepared["world"]["base"]
            ready = marker_root / "commit-ready"
            release = marker_root / "commit-release"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = SRC
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    child,
                    json.dumps(invocation, sort_keys=True),
                    str(ready),
                    str(release),
                ],
                cwd=PROJECT_ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() and process.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("child did not reach the pre-COMMIT rendezvous")
                    time.sleep(0.0005)
                self.assertIsNone(process.poll())
                release.write_bytes(b"release\n")
                state_directory = prepared["main_db"].parent
                master_prefix = prepared["main_db"].name + "-mj"
                while process.poll() is None and time.monotonic() < deadline:
                    if any(
                        entry.name.startswith(master_prefix)
                        for entry in state_directory.iterdir()
                    ):
                        observed = True
                        os.kill(process.pid, signal.SIGKILL)
                        break
                process.wait(timeout=20)
                if observed:
                    self.assertEqual(process.returncode, -signal.SIGKILL)
                    recovered = self._process_one(prepared)
                    self.assertTrue(recovered.endswith(b"\n"))
                    self.assertEqual(
                        self._logical_process_counts(prepared),
                        {"receipts": 1, "assessments": 1, "events": 1},
                    )
                    with contextlib.closing(
                        sqlite3.connect(prepared["vac_db"])
                    ) as vacancy:
                        self.assertEqual(
                            vacancy.execute(
                                "SELECT COUNT(*) FROM normalised_jobs"
                            ).fetchone()[0],
                            1,
                        )
                    self.assertEqual(self._process_one(prepared), recovered)
                    break
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
        self.assertTrue(
            observed,
            f"SQLite master-journal commit state was not observed in {attempts} attempts",
        )

    def test_recovery_reopens_real_empty_and_complete_attached_state(self):
        import unittest.mock as mock

        pm = processing_module
        for durable in ("empty", "complete"):
            with self.subTest(durable=durable):
                prepared = self._prepare_process_one()
                plans = []
                original_builder = pm.build_prospective_plan

                def capture_plan(*args, **kwargs):
                    plan = original_builder(*args, **kwargs)
                    plans.append(plan)
                    return plan

                with mock.patch.object(
                    pm, "build_prospective_plan", side_effect=capture_plan
                ):
                    if durable == "empty":
                        pm.install_fault(
                            "before_process_one_commit", RuntimeError("caught")
                        )
                        try:
                            with self.assertRaisesRegex(RuntimeError, "caught"):
                                self._process_one(prepared)
                        finally:
                            pm.clear_faults()
                    else:
                        created = self._process_one(prepared)
                self.assertEqual(len(plans), 1)
                recovered = pm.recover_process_one_durable_truth(
                    prepared["world"]["data"],
                    prepared["name"],
                    plans[0],
                )
                self.assertEqual(recovered.disposition, durable)
                if durable == "complete":
                    self.assertEqual(recovered.stored_receipt_bytes, created)
                else:
                    self.assertIsNone(recovered.stored_receipt_bytes)

    def test_recovery_ignores_mutable_raw_and_profile_after_exact_commit(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare_process_one()
        plans = []
        original_builder = pm.build_prospective_plan

        def capture_plan(*args, **kwargs):
            plan = original_builder(*args, **kwargs)
            plans.append(plan)
            return plan

        with mock.patch.object(
            pm, "build_prospective_plan", side_effect=capture_plan
        ):
            created = self._process_one(prepared)
        self.assertEqual(len(plans), 1)
        profile_directory = (
            prepared["world"]["data"]
            / "profiles"
            / prepared["payload"]["profile_id"]
        )
        os.rename(profile_directory, profile_directory.with_name("profile-gone"))
        with contextlib.closing(sqlite3.connect(prepared["vac_db"])) as vacancy:
            vacancy.execute(
                "DELETE FROM postings WHERE key=?",
                (prepared["payload"]["job_key"],),
            )
            vacancy.commit()
        recovered = pm.recover_process_one_durable_truth(
            prepared["world"]["data"], prepared["name"], plans[0]
        )
        self.assertEqual(
            recovered.disposition, pm.RECOVERY_DURABLE_COMPLETE
        )
        self.assertEqual(recovered.stored_receipt_bytes, created)

    def test_recovery_returns_incoherent_for_partial_real_graph(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare_process_one()
        plans = []
        original_builder = pm.build_prospective_plan

        def capture_plan(*args, **kwargs):
            plan = original_builder(*args, **kwargs)
            plans.append(plan)
            return plan

        with mock.patch.object(
            pm, "build_prospective_plan", side_effect=capture_plan
        ):
            self._process_one(prepared)
        with contextlib.closing(sqlite3.connect(prepared["vac_db"])) as vacancy:
            vacancy.execute(
                "DELETE FROM normalised_jobs WHERE key=?",
                (prepared["payload"]["job_key"],),
            )
            vacancy.commit()
        recovered = pm.recover_process_one_durable_truth(
            prepared["world"]["data"], prepared["name"], plans[0]
        )
        self.assertEqual(
            recovered.disposition, pm.RECOVERY_DURABLE_INCOHERENT
        )
        self.assertIsNone(recovered.stored_receipt_bytes)

    def test_recovery_rejects_database_inode_substitution_before_sqlite(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare_process_one()
        plans = []
        original_builder = pm.build_prospective_plan

        def capture_plan(*args, **kwargs):
            plan = original_builder(*args, **kwargs)
            plans.append(plan)
            return plan

        with mock.patch.object(
            pm, "build_prospective_plan", side_effect=capture_plan
        ):
            self._process_one(prepared)
        replacement = prepared["main_db"].with_suffix(".replacement")
        shutil.copyfile(prepared["main_db"], replacement)
        os.chmod(replacement, 0o600)
        os.replace(replacement, prepared["main_db"])
        with self.assertRaises(pm.ProcessingRefused) as caught:
            pm.recover_process_one_durable_truth(
                prepared["world"]["data"], prepared["name"], plans[0]
            )
        self.assertEqual(caught.exception.reason, pm.REASON_CONFIG_DATABASE)

    def test_recovery_snapshot_blocks_both_database_writers_and_is_read_only(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare_process_one()
        plans = []
        original_builder = pm.build_prospective_plan

        def capture_plan(*args, **kwargs):
            plan = original_builder(*args, **kwargs)
            plans.append(plan)
            return plan

        with mock.patch.object(
            pm, "build_prospective_plan", side_effect=capture_plan
        ):
            created = self._process_one(prepared)
        original_verify = pm.verify_recovered_connection
        writer_results = []

        def verify_with_writer_probe(connection, plan):
            if not writer_results:
                for path in (prepared["main_db"], prepared["vac_db"]):
                    with contextlib.closing(
                        sqlite3.connect(path, timeout=0.01)
                    ) as writer:
                        try:
                            writer.execute("BEGIN IMMEDIATE")
                        except sqlite3.OperationalError as exc:
                            writer_results.append(str(exc))
                        else:
                            writer.rollback()
                            writer_results.append("accepted")
            return original_verify(connection, plan)

        traced = []
        original_open = pm._open_read_view

        def traced_open(*args, **kwargs):
            connection = original_open(*args, **kwargs)
            connection.set_trace_callback(traced.append)
            return connection

        with (
            mock.patch.object(
                pm,
                "verify_recovered_connection",
                side_effect=verify_with_writer_probe,
            ),
            mock.patch.object(pm, "_open_read_view", side_effect=traced_open),
        ):
            recovered = pm.recover_process_one_durable_truth(
                prepared["world"]["data"], prepared["name"], plans[0]
            )
        self.assertEqual(writer_results, ["database is locked"] * 2)
        self.assertEqual(
            recovered.disposition, pm.RECOVERY_DURABLE_COMPLETE
        )
        self.assertEqual(recovered.stored_receipt_bytes, created)
        forbidden = ("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")
        self.assertFalse(
            any(statement.lstrip().upper().startswith(forbidden) for statement in traced),
            traced,
        )

    def test_recovery_has_no_raw_profile_or_application_write_owner(self):
        source = inspect.getsource(
            processing_module.recover_process_one_durable_truth
        )
        source += inspect.getsource(processing_module._open_recovery_admission)
        for forbidden in (
            "admit_raw_snapshot",
            "coherent_snapshot",
            "ProfileStore",
            "read_posting",
            "apply_transaction_plan",
            "apply_on(",
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            ".commit(",
            "LLMClient",
            "playwright",
            "browser",
        ):
            self.assertNotIn(forbidden, source)

    def test_recovery_fault_after_first_verification_never_claims_success(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare_process_one()
        plans = []
        original_builder = pm.build_prospective_plan

        def capture_plan(*args, **kwargs):
            plan = original_builder(*args, **kwargs)
            plans.append(plan)
            return plan

        with mock.patch.object(
            pm, "build_prospective_plan", side_effect=capture_plan
        ):
            self._process_one(prepared)
        pm.install_fault(
            "after_recovery_first_verify", RuntimeError("recovery-race")
        )
        try:
            with self.assertRaises(pm.ProcessingRefused) as caught:
                pm.recover_process_one_durable_truth(
                    prepared["world"]["data"], prepared["name"], plans[0]
                )
        finally:
            pm.clear_faults()
        self.assertEqual(
            caught.exception.reason, pm.REASON_RECOVERY_INCOHERENT
        )
        self.assertIn("recovery-race", caught.exception.detail)

    def test_process_one_same_operation_threads_create_once_and_replay_exact(self):
        pm = processing_module
        prepared = self._prepare_process_one()
        barrier = threading.Barrier(3)
        results: list[bytes] = []
        errors: list[BaseException] = []
        commit_calls = 0
        counter_lock = threading.Lock()
        original_commit = pm._commit_process_one

        def counted_commit(*args, **kwargs):
            nonlocal commit_calls
            with counter_lock:
                commit_calls += 1
            return original_commit(*args, **kwargs)

        def worker():
            try:
                barrier.wait(timeout=5)
                results.append(self._process_one(prepared))
            except BaseException as exc:
                errors.append(exc)

        pm._commit_process_one = counted_commit
        self.addCleanup(setattr, pm, "_commit_process_one", original_commit)
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertTrue(results[0].endswith(b"\n"))
        self.assertEqual(commit_calls, 1)
        self.assertEqual(
            self._logical_process_counts(prepared),
            {"receipts": 1, "assessments": 1, "events": 1},
        )

    def test_process_one_same_operation_processes_create_once_and_replay_exact(self):
        prepared = self._prepare_process_one()
        invocation = {
            "data_home": str(prepared["world"]["data"]),
            "envelope_name": prepared["name"],
            "cli": self._cli(prepared["payload"]),
        }
        code = """
import base64
import json
import pathlib
import sys
from market_aligner.processing import process_one

invocation = json.loads(sys.argv[1])
sys.stdin.buffer.read(1)
try:
    receipt = process_one(
        pathlib.Path(invocation["data_home"]),
        invocation["envelope_name"],
        **invocation["cli"],
    )
except BaseException as exc:
    print(json.dumps({
        "ok": False,
        "type": type(exc).__name__,
        "reason": getattr(exc, "reason", None),
        "detail": getattr(exc, "detail", repr(exc)),
    }, sort_keys=True))
else:
    print(json.dumps({
        "ok": True,
        "receipt": base64.b64encode(receipt).decode("ascii"),
    }, sort_keys=True))
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = SRC
        args = [sys.executable, "-c", code, json.dumps(invocation, sort_keys=True)]
        processes = [
            subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                env=env,
            )
            for _ in range(2)
        ]
        outputs: list[dict[str, typing.Any]] = []
        try:
            for process in processes:
                assert process.stdin is not None
                process.stdin.write(b"x")
                process.stdin.close()
            for process in processes:
                assert process.stdout is not None and process.stderr is not None
                process.wait(timeout=20)
                stdout = process.stdout.read().decode("utf-8")
                stderr = process.stderr.read().decode("utf-8")
                process.stdout.close()
                process.stderr.close()
                self.assertEqual(process.returncode, 0, stderr)
                outputs.append(json.loads(stdout))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
        self.assertEqual([item["ok"] for item in outputs], [True, True])
        receipts = [base64.b64decode(item["receipt"]) for item in outputs]
        self.assertEqual(receipts[0], receipts[1])
        self.assertTrue(receipts[0].endswith(b"\n"))
        self.assertEqual(
            self._logical_process_counts(prepared),
            {"receipts": 1, "assessments": 1, "events": 1},
        )

    def test_process_one_changed_contender_waits_then_refuses_reason6(self):
        pm = processing_module
        prepared = self._prepare_process_one()
        changed_payload = copy.deepcopy(prepared["payload"])
        changed_payload.pop("_staged_name", None)
        changed_payload["extraction"]["receipt"]["model"] = "changed-model"
        changed = dict(prepared)
        changed["payload"] = changed_payload
        changed["name"] = self._stage(prepared["world"], changed_payload)

        entered_commit = threading.Event()
        release_commit = threading.Event()
        original_commit = pm._commit_process_one
        winner: list[bytes] = []
        loser_errors: list[BaseException] = []

        def held_commit(*args, **kwargs):
            entered_commit.set()
            if not release_commit.wait(timeout=10):
                raise TimeoutError("test did not release the winning commit")
            return original_commit(*args, **kwargs)

        def run_winner():
            winner.append(self._process_one(prepared))

        def run_loser():
            try:
                self._process_one(changed)
            except BaseException as exc:
                loser_errors.append(exc)

        pm._commit_process_one = held_commit
        self.addCleanup(setattr, pm, "_commit_process_one", original_commit)
        first = threading.Thread(target=run_winner)
        second = threading.Thread(target=run_loser)
        try:
            first.start()
            self.assertTrue(entered_commit.wait(timeout=10))
            second.start()
            time.sleep(0.05)
            self.assertTrue(second.is_alive())
        finally:
            release_commit.set()
            first.join(timeout=15)
            second.join(timeout=15)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(len(winner), 1)
        self.assertEqual(len(loser_errors), 1)
        self.assertIsInstance(loser_errors[0], pm.ProcessingRefused)
        self.assertEqual(
            typing.cast(pm.ProcessingRefused, loser_errors[0]).reason,
            pm.REASON_EXISTING_RECEIPT,
        )
        self.assertEqual(
            self._logical_process_counts(prepared),
            {"receipts": 1, "assessments": 1, "events": 1},
        )

    def test_process_one_post_preflight_replacements_roll_back_before_dml(self):
        pm = processing_module
        for label, target_key, expected_reason in (
            ("envelope", "envelope", pm.REASON_ENVELOPE_PATH),
            ("config", "config", pm.REASON_CONFIG_DATABASE),
            ("database", "database", pm.REASON_CONFIG_DATABASE),
        ):
            with self.subTest(label=label):
                prepared = self._prepare_process_one()
                targets = {
                    "envelope": (
                        prepared["world"]["data"]
                        / "state"
                        / "processing-inbox"
                        / prepared["name"]
                    ),
                    "config": pathlib.Path(
                        prepared["payload"]["config"]["source_path"]
                    ),
                    "database": pathlib.Path(prepared["vac_db"]),
                }
                target = targets[target_key]
                backup = pathlib.Path(self.root) / f"{label}-authority-backup"

                def substitute():
                    os.rename(target, backup)
                    replacement_bytes = backup.read_bytes()
                    if label == "config":
                        replacement_bytes += b"\n# post-preflight drift\n"
                    target.write_bytes(replacement_bytes)
                    os.chmod(target, 0o600)

                pm.install_fault("before_process_one_begin", substitute)
                try:
                    with self.assertRaises(pm.ProcessingRefused) as refused:
                        self._process_one(prepared)
                    self.assertEqual(refused.exception.reason, expected_reason)
                    self.assertEqual(
                        self._logical_process_counts(prepared),
                        {"receipts": 0, "assessments": 0, "events": 0},
                    )
                    with contextlib.closing(
                        sqlite3.connect(prepared["vac_db"])
                    ) as vacancy:
                        self.assertEqual(
                            vacancy.execute(
                                "SELECT COUNT(*) FROM normalised_jobs"
                            ).fetchone()[0],
                            0,
                        )
                finally:
                    pm.clear_faults()
                    if backup.exists():
                        target.unlink(missing_ok=True)
                        os.rename(backup, target)
                self.assertTrue(self._process_one(prepared).endswith(b"\n"))

    def test_projection_conflict_precedes_provisional_atomic_store(self):
        pm = processing_module
        prepared = self._prepare_process_one()
        with contextlib.closing(sqlite3.connect(prepared["main_db"])) as main:
            main.execute(pm.FIT001_RECEIPTS_DDL)
            main.commit()
        with contextlib.closing(sqlite3.connect(prepared["vac_db"])) as vacancy:
            vacancy.execute(
                "INSERT INTO normalised_jobs(key,normalized_json,normalized_at)"
                " VALUES(?,?,?)",
                (
                    prepared["payload"]["job_key"],
                    '{"different":true}',
                    self.RECEIPT_T,
                ),
            )
            vacancy.commit()
        with self.assertRaises(pm.ProcessingRefused) as refused:
            self._process_one(prepared)
        self.assertEqual(refused.exception.reason, pm.REASON_PROJECTION_CONFLICT)
        self.assertEqual(self._logical_process_counts(prepared), {
            "receipts": 0, "assessments": 0, "events": 0,
        })


class StageDPart3B2UriHelperTests(TempRootTestCase):
    """Focused authority for the deterministic SQLite file-URI helper."""

    REPRESENTATIVE_NAMES = (
        "plain.db",
        "with space.db",
        "hash#tag.db",
        "query?mark.db",
        "percent%25only.db",
        "caf\u00e9_\u00fcnicode.db",
    )

    def test_equivalent_to_as_uri_for_representatives(self) -> None:

        root = pathlib.Path(self.root)
        root.mkdir(parents=True, exist_ok=True)
        for name in self.REPRESENTATIVE_NAMES:
            with self.subTest(name=name):
                target = root / name
                target.write_bytes(b"")
                ours = processing_module._sqlite_file_uri(target)
                baseline = target.as_uri()
                self.assertTrue(ours.startswith("file://"))
                self.assertEqual(ours, baseline)
                self.assertNotIn(" ", ours)
                import re as _re

                for escape in _re.findall(r"%([0-9A-Fa-f]{2})", ours):
                    self.assertEqual(escape, escape.upper())

    def test_real_sqlite_mode_rw_opens_each_representative(self) -> None:
        root = pathlib.Path(self.root)
        for name in self.REPRESENTATIVE_NAMES:
            with self.subTest(name=name):
                target = root / name
                seed = sqlite3.connect(str(target))
                try:
                    seed.execute("CREATE TABLE probe(id INTEGER)")
                    seed.execute("INSERT INTO probe VALUES(7)")
                    seed.commit()
                finally:
                    seed.close()
                uri = processing_module._sqlite_file_uri(target) + "?mode=rw"
                conn = sqlite3.connect(uri, uri=True)
                try:
                    conn.execute("INSERT INTO probe VALUES(8)")
                    conn.commit()
                    total = conn.execute(
                        "SELECT COUNT(*) FROM probe"
                    ).fetchone()[0]
                finally:
                    conn.close()
                self.assertEqual(total, 2)

    def test_relative_and_nul_refuse_before_any_sqlite_use(self) -> None:
        with self.assertRaises(ValueError) as relative:
            processing_module._sqlite_file_uri(pathlib.Path("relative/thing.db"))
        self.assertIn("absolute", str(relative.exception))
        with self.assertRaises(ValueError) as nul:
            processing_module._sqlite_file_uri(
                pathlib.Path("/data/with\0nul.db")
            )
        self.assertIn("NUL", str(nul.exception))


class StageDPart3C1AssessmentCasTests(TempRootTestCase):
    """Part-3C C1: caller-owned score/event read-plan and CAS helpers."""

    PID = "prf_" + "a" * 32
    K = "boards.example:j-1"
    K2 = "boards.example:j-2"
    TS = "2026-08-25T12:00:00.000000+00:00"

    _db_counter = 0

    def _store(self, *, unique=False):
        from market_aligner.research.store import AssessmentStore

        root = pathlib.Path(self.root) / "state"
        root.mkdir(parents=True, exist_ok=True)
        if unique:
            type(self)._db_counter += 1
            name = f"research-{type(self)._db_counter}.sqlite3"
        else:
            name = "research.sqlite3"
        return AssessmentStore(root / name)

    def _conn(self, store=None, *, busy_ms=250):
        store = store or self._store()
        conn = store.connect()
        conn.execute(f"PRAGMA busy_timeout={busy_ms}")
        self.addCleanup(conn.close)
        return conn

    def _result(self, key=None, **overrides):
        from market_aligner.assessment.scoring import (
            FitStatus,
            ScoreResult,
            ScoringParams,
        )

        node = {
            "profile_id": self.PID,
            "job_key": key or self.K,
            "track": "backend",
            "fit": 0.42,
            "opportunity": 0.555,
            "final": 48.75,
            "fit_status": FitStatus.UNCALIBRATED,
            "parameters_hash": ScoringParams().parameters_hash,
            "fit_subscores": {
                "interest": 0.4,
                "demonstrated_skill": 0.5,
                "market_readiness": 0.3,
                "technical_alignment": 0.6,
                "evidence_match": 0.5,
            },
            "opportunity_subscores": {
                "market_demand": 0.0,
                "accessibility": 1.0,
                "growth_potential": 0.0,
            },
        }
        node.update(overrides)
        return ScoreResult(**node)

    def _seed_row(self, conn, key=None, **column_overrides):
        from market_aligner.assessment.scoring import FitStatus

        result = self._result(key=key)
        payload, digest = research_store_module.canonical_score_payload(result)
        columns = {
            "profile_id": self.PID,
            "job_key": key or self.K,
            "url": "https://boards.example/listing/j-1",
            "title": "Senior Backend Engineer",
            "company": "",
            "opportunity": 0.555,
            "fit": 0.42,
            "final_score": 48.75,
            "fit_status": FitStatus.UNCALIBRATED.value,
            "extraction_confidence": 0.9,
            "score_payload_json": payload,
            "score_payload_hash": digest,
            "state": "scored",
            "created_at": self.TS,
            "updated_at": self.TS,
        }
        columns.update(column_overrides)
        names = ",".join(columns)
        marks = ",".join("?" for _ in columns)
        conn.execute(
            f"INSERT INTO assessments({names}) VALUES({marks})",
            tuple(columns.values()),
        )
        conn.commit()
        return columns

    # ------------------------------------------------------------- helpers

    def test_canonical_payload_matches_legacy_formula_exactly(self) -> None:
        import json as json_module

        result = self._result()
        legacy = json_module.dumps(
            dataclasses.asdict(result),
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        payload, digest = research_store_module.canonical_score_payload(result)
        self.assertIsInstance(payload, str)
        self.assertEqual(payload, legacy)
        self.assertEqual(digest, hashlib.sha256(legacy.encode("utf-8")).hexdigest())

    def test_unicode_job_keys_hash_distinctly_byte_identically(self) -> None:
        nfc = self._result(key="caf\u00e9:j-1")
        nfd = self._result(key="cafe\u0301:j-1")
        _, digest_nfc = research_store_module.canonical_score_payload(nfc)
        _, digest_nfd = research_store_module.canonical_score_payload(nfd)
        self.assertNotEqual(digest_nfc, digest_nfd)

    def test_upsert_score_reuses_helper_bytes(self) -> None:
        store = self._store()
        result = self._result()
        store.upsert_score(
            result,
            url="https://x",
            title="t",
            company="",
            extraction_confidence=0.9,
        )
        row = store.assessment(result.profile_id, result.job_key)
        payload, digest = research_store_module.canonical_score_payload(result)
        self.assertEqual(row["score_payload_json"], payload)
        self.assertEqual(row["score_payload_hash"], digest)

    # --------------------------------------------------- ownership/statics

    def test_helpers_never_open_connections_or_own_transactions(self) -> None:
        conn = self._conn()
        original_connect = sqlite3.connect

        def bomb(*args, **kwargs):
            raise AssertionError("helper attempted to open a connection")

        sqlite3.connect = bomb
        try:
            score_outcome = research_store_module.cas_accepted_score(
                conn,
                result=self._result(),
                url="https://x",
                title="t",
                company="",
                extraction_confidence=0.9,
                accepted_at=self.TS,
            )
            self.assertEqual(score_outcome.action, "insert")
            event_outcome = research_store_module.cas_processing_event(
                conn,
                profile_id=self.PID,
                job_key=self.K,
                event_type="processing_score_accepted",
                actor_kind="deterministic",
                payload_json="{}",
                idempotency_key="processing-score:" + self.PID + ":" + "a" * 8,
                created_at=self.TS,
                event_id=1,
            )
            self.assertEqual(event_outcome.action, "insert")
        finally:
            sqlite3.connect = original_connect
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0], 1
        )

    def test_static_sources_contain_no_update_ignore_or_transaction_control(self) -> None:
        import inspect

        forbidden = (
            "UPDATE ",
            "INSERT OR IGNORE",
            "ON CONFLICT",
            "executescript",
            "BEGIN ",
            ".commit(",
            ".rollback(",
            "sqlite3.connect(",
            "PRAGMA journal_mode",
            "COMMIT",
            "ROLLBACK",
        )
        self.assertEqual(
            inspect.getsource(research_store_module).count(
                "def canonical_score_payload"
            ),
            1,
        )
        helpers = (
            research_store_module.canonical_score_payload,
            research_store_module.plan_accepted_score,
            research_store_module.execute_score_insert,
            research_store_module.cas_accepted_score,
            research_store_module.plan_processing_event,
            research_store_module.execute_processing_event_insert,
            research_store_module.cas_processing_event,
        )
        for helper in helpers:
            source = inspect.getsource(helper)
            for token in forbidden:
                self.assertNotIn(token, source, f"{helper.__name__}: {token}")

    # ------------------------------------------------------- score plans

    def test_insert_plan_sets_created_updated_accepted_equal(self) -> None:
        conn = self._conn()
        plan = research_store_module.plan_accepted_score(
            conn,
            result=self._result(),
            url="https://x",
            title="t",
            company="",
            extraction_confidence=0.9,
            accepted_at=self.TS,
        )
        self.assertEqual(plan.action, "insert")
        self.assertEqual(plan.insert.created_at, self.TS)
        before = conn.total_changes
        research_store_module.execute_score_insert(conn, plan.insert)
        self.assertEqual(conn.total_changes - before, 1)
        row = conn.execute(
            "SELECT * FROM assessments WHERE profile_id=? AND job_key=?",
            (self.PID, self.K),
        ).fetchone()
        self.assertEqual(row["created_at"], self.TS)
        self.assertEqual(row["updated_at"], self.TS)

    def test_cas_insert_returns_exact_durable_projection(self) -> None:
        conn = self._conn()
        outcome = research_store_module.cas_accepted_score(
            conn,
            result=self._result(),
            url="https://x",
            title="t",
            company="",
            extraction_confidence=0.9,
            accepted_at=self.TS,
        )
        self.assertEqual(outcome.action, "insert")
        projection = outcome.projection
        for field in (
            "profile_id", "job_key", "url", "title", "company", "opportunity",
            "fit", "final_score", "fit_status", "extraction_confidence",
            "score_payload_json", "score_payload_hash", "state",
            "created_at", "updated_at",
        ):
            self.assertTrue(hasattr(projection, field), field)
        self.assertEqual(projection.created_at, self.TS)
        self.assertEqual(projection.updated_at, self.TS)
        self.assertIsInstance(projection, research_store_module.AcceptedScoreProjection)

    def test_cas_reuse_performs_zero_dml_and_preserves_timestamps(self) -> None:
        conn = self._conn()
        self._seed_row(
            conn, created_at=self.TS, updated_at="2026-08-26T00:00:00Z"
        )
        conn.commit()
        before = conn.total_changes
        outcome = research_store_module.cas_accepted_score(
            conn,
            result=self._result(),
            url="https://boards.example/listing/j-1",
            title="Senior Backend Engineer",
            company="",
            extraction_confidence=0.9,
            accepted_at=self.TS,
        )
        self.assertEqual(outcome.action, "reuse")
        self.assertEqual(outcome.plan.reuse.created_at, self.TS)
        self.assertEqual(
            outcome.plan.reuse.updated_at, "2026-08-26T00:00:00Z"
        )
        projection = outcome.projection
        self.assertEqual(projection.created_at, self.TS)
        self.assertEqual(projection.updated_at, "2026-08-26T00:00:00Z")
        self.assertNotEqual(projection.created_at, projection.updated_at)
        self.assertEqual(conn.total_changes - before, 0)

    def test_caller_rollback_discards_helper_insert(self) -> None:
        conn = self._conn()
        conn.execute("BEGIN")
        research_store_module.cas_accepted_score(
            conn,
            result=self._result(),
            url="https://x",
            title="t",
            company="",
            extraction_confidence=None,
            accepted_at=self.TS,
        )
        conn.rollback()
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0], 0
        )

    def _refused_projection(self, callable_, fragment=None):
        with self.assertRaises(research_store_module.ProjectionConflict) as raised:
            callable_()
        if fragment:
            self.assertIn(fragment, str(raised.exception))
        return raised.exception

    def test_every_field_substitution_conflicts_on_reuse(self) -> None:
        base_overrides = {
            "url": "https://other",
            "title": "Other",
            "company": "OtherCo",
            "opportunity": 0.554,
            "fit": 0.421,
            "final_score": 48.74,
            "score_payload_json": "{}",
            "score_payload_hash": "a" * 64,
            "state": "employer_researched",
            "opportunity_decision": "pass",
            "opportunity_reason": "why",
            "policy_hash": "b" * 64,
            "created_at": "not-a-timestamp",
            "updated_at": "2026-13-01T00:00:00Z",
        }
        for column, override in base_overrides.items():
            with self.subTest(column=column):
                conn = self._conn(store=self._store(unique=True))
                try:
                    self._seed_row(conn, **{column: override})
                    self._refused_projection(
                        lambda c=conn: research_store_module.plan_accepted_score(
                            c,
                            result=self._result(),
                            url="https://boards.example/listing/j-1",
                            title="Senior Backend Engineer",
                            company="",
                            extraction_confidence=0.9,
                            accepted_at=self.TS,
                        )
                    )
                finally:
                    conn.close()

    def test_type_and_bool_stored_values_are_conflicts(self) -> None:
        base_row = {
            "profile_id": self.PID,
            "job_key": self.K,
            "opportunity": 0.555,
            "fit": 0.42,
            "final_score": 48.75,
            "extraction_confidence": None,
            "url": "u", "title": "t", "company": "",
            "fit_status": "uncalibrated",
            "score_payload_json": "{}",
            "score_payload_hash": "d" * 64,
            "state": "scored",
            "opportunity_decision": None,
            "opportunity_reason": None,
            "policy_hash": None,
            "created_at": self.TS,
            "updated_at": self.TS,
        }
        expected = dict(
            expected_profile_id=self.PID, expected_job_key=self.K,
            expected_url="u", expected_title="t", expected_company="",
            expected_opportunity=0.555, expected_fit=0.42,
            expected_final=48.75, expected_status="uncalibrated",
            expected_confidence=None, expected_payload="{}",
            expected_digest="d" * 64,
        )

        problems = research_store_module._score_row_problems(
            {**base_row, "fit": True, "final_score": "48.75"}, **expected
        )
        self.assertTrue(any("stored fit" in p for p in problems), problems)
        self.assertTrue(any("stored final_score" in p for p in problems))

        ranged = research_store_module._score_row_problems(
            {**base_row, "opportunity": 1.5}, **expected
        )
        self.assertTrue(
            any("stored opportunity must be in" in p for p in ranged),
            ranged,
        )
        int_type = research_store_module._score_row_problems(
            {**base_row, "opportunity": True}, **expected
        )
        self.assertTrue(any("stored opportunity must be an int" in p
                            for p in int_type), int_type)

        status = research_store_module._score_row_problems(
            {**base_row, "fit_status": "calibrated"}, **expected
        )
        self.assertTrue(any("fit_status differs" in p for p in status), status)

        advanced = research_store_module._score_row_problems(
            {**base_row, "opportunity_decision": "pass",
             "opportunity_reason": "why", "policy_hash": "b" * 64},
            **expected
        )
        self.assertEqual(len(advanced), 3, advanced)
        self.assertTrue(all("advanced and non-null" in p for p in advanced))

    def test_nonfinite_result_values_conflict(self) -> None:
        conn = self._conn()
        for field in ("fit", "opportunity", "final"):
            with self.subTest(field=field):
                self._refused_projection(
                    lambda f=field: research_store_module.plan_accepted_score(
                        conn,
                        result=self._result(**{f: float("nan")}),
                        url="u", title="t", company="",
                        extraction_confidence=None,
                        accepted_at=self.TS,
                    )
                )

    def test_null_vs_value_extraction_confidence_both_directions(self) -> None:
        for stored in (None, 0.8):
            with self.subTest(stored=stored):
                conn = self._conn(store=self._store(unique=True))
                self._seed_row(conn, extraction_confidence=stored)
                self._refused_projection(
                    lambda c=conn: research_store_module.plan_accepted_score(
                        c,
                        result=self._result(),
                        url="https://boards.example/listing/j-1",
                        title="Senior Backend Engineer",
                        company="",
                        extraction_confidence=0.9,
                        accepted_at=self.TS,
                    )
                )

    def test_bool_confidence_param_is_refused(self) -> None:
        conn = self._conn()
        self._refused_projection(
            lambda: research_store_module.plan_accepted_score(
                conn,
                result=self._result(),
                url="u",
                title="t",
                company="",
                extraction_confidence=True,
                accepted_at=self.TS,
            )
        )

    def test_exact_profile_identity_required(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        for bad in (" " + self.PID, self.PID + " ", 5):
            label = repr(bad)
            with self.subTest(profile_id=label):
                self._refused_projection(
                    lambda b=bad: research_store_module.plan_accepted_score(
                        conn,
                        result=self._result(profile_id=b),
                        url="u", title="t", company="",
                        extraction_confidence=None,
                        accepted_at=self.TS,
                    )
                )
                self._refused_projection(
                    lambda b=bad: research_store_module.plan_processing_event(
                        conn,
                        profile_id=b,
                        job_key=self.K,
                        event_type="processing_score_accepted",
                        actor_kind="deterministic",
                        payload_json="{}",
                        idempotency_key="k",
                        created_at=self.TS,
                        event_id=60,
                    )
                )

    def test_rfc3339_timestamp_length_bounds(self) -> None:
        conn = self._conn()
        base = dict(
            result=self._result(), url="u", title="t", company="",
            extraction_confidence=None,
        )
        short = "2026-08-25T12:00:0Z"
        self.assertEqual(len(short), 19)
        long_ts = "2026-08-25T12:00:00." + "1" * 45 + "+00:00"
        self.assertGreater(len(long_ts), 64)
        for bad in (short, long_ts):
            with self.subTest(length=len(bad)):
                self._refused_projection(
                    lambda t=bad: research_store_module.plan_accepted_score(
                        conn, accepted_at=t, **base
                    )
                )
        edge20 = "2026-08-25T12:00:00Z"
        edge64 = "2026-08-25T12:00:00." + "1" * 38 + "+00:00"
        self.assertEqual(len(edge20), 20)
        self.assertEqual(len(edge64), 64)
        for good in (edge20, edge64):
            with self.subTest(length=len(good)):
                unique_conn = self._conn(store=self._store(unique=True))
                try:
                    plan = research_store_module.plan_accepted_score(
                        unique_conn, accepted_at=good, **base
                    )
                    self.assertEqual(plan.action, "insert")
                    self.assertEqual(plan.insert.created_at, good)
                finally:
                    unique_conn.close()

    def test_event_cas_reuse_public_zero_dml_exact_facts(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )
        first = research_store_module.cas_processing_event(conn, event_id=3, **kwargs)
        self.assertEqual(first.action, "insert")
        before = conn.total_changes
        outcome = research_store_module.cas_processing_event(conn, event_id=3, **kwargs)
        self.assertEqual(outcome.action, "reuse")
        self.assertEqual(conn.total_changes - before, 0)
        projection = outcome.projection
        self.assertEqual(projection.event_id, 3)
        self.assertEqual(projection.profile_id, self.PID)
        self.assertEqual(projection.job_key, self.K)
        self.assertEqual(projection.event_type, kwargs["event_type"])
        self.assertEqual(projection.actor_kind, kwargs["actor_kind"])
        self.assertEqual(projection.payload_json, "{}")
        self.assertEqual(projection.idempotency_key, kwargs["idempotency_key"])
        self.assertEqual(projection.created_at, self.TS)

    def test_score_reuse_plan_to_reread_drift_conflicts(self) -> None:
        columns = research_store_module._SCORE_ROW_COLUMNS
        conn = self._conn()
        self._seed_row(conn)
        drift_index = columns.index("score_payload_hash")

        class _Tampered:
            def __init__(self, values):
                self._values = values

            def fetchone(self):
                return self._values

        class _DriftConnection:
            def __init__(self, inner):
                self._inner = inner
                self.selects = 0

            def execute(self, sql, params=()):
                result = self._inner.execute(sql, params)
                if (
                    sql.lstrip().upper().startswith("SELECT")
                    and "FROM assessments WHERE profile_id" in sql
                ):
                    self.selects += 1
                    if self.selects == 2:
                        values = list(result.fetchone())
                        values[drift_index] = "e" * 64
                        return _Tampered(values)
                return result

        drifted = _DriftConnection(conn)
        exc = self._refused_projection(
            lambda: research_store_module.cas_accepted_score(
                drifted,
                result=self._result(),
                url="https://boards.example/listing/j-1",
                title="Senior Backend Engineer",
                company="",
                extraction_confidence=0.9,
                accepted_at=self.TS,
            )
        )
        self.assertIn("drifted between plan and reread", str(exc))

    def test_score_insert_integrity_maps_to_conflict(self) -> None:
        class _EmptyCursor:
            def fetchone(self):
                return None

        class _BombConnection:
            def execute(self, sql, params=()):
                if sql.lstrip().upper().startswith("INSERT INTO"):
                    raise sqlite3.IntegrityError("UNIQUE constraint failed")
                if sql.lstrip().upper().startswith("SELECT"):
                    return _EmptyCursor()
                raise AssertionError("unexpected statement")

        self._refused_projection(
            lambda: research_store_module.cas_accepted_score(
                _BombConnection(),
                result=self._result(),
                url="u", title="t", company="",
                extraction_confidence=None,
                accepted_at=self.TS,
            ),
            fragment="integrity race",
        )

    def test_event_reuse_reread_drift_conflicts(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )
        research_store_module.cas_processing_event(conn, event_id=3, **kwargs)
        before = conn.total_changes
        drift_column = "payload_json"

        class _Tampered:
            def __init__(self, values):
                self._values = values

            def fetchone(self):
                return self._values

        class _Drift:
            def __init__(self, inner):
                self._inner = inner

            def execute(self, sql, params=()):
                result = self._inner.execute(sql, params)
                if (
                    sql.lstrip().upper().startswith("SELECT")
                    and "FROM assessment_events WHERE id=?" in sql
                ):
                    values = list(result.fetchone())
                    values[
                        research_store_module._EVENT_PROJECTION_COLUMNS.index(
                            drift_column
                        )
                    ] = '{"tampered": true}'
                    return _Tampered(values)
                return result

        exc = self._refused_projection(
            lambda: research_store_module.cas_processing_event(
                _Drift(conn), event_id=3, **kwargs
            )
        )
        self.assertIn("drifted between plan and reread", str(exc))
        self.assertIn("payload_json", str(exc))
        self.assertEqual(conn.total_changes - before, 0)

    def test_event_insert_reread_drift_conflicts(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )

        class _Tampered:
            def __init__(self, values):
                self._values = values

            def fetchone(self):
                return self._values

        class _InsertRereadDrift:
            """Passes the INSERT through; tampers with the first reread."""

            def __init__(self, inner):
                self._inner = inner
                self.inserted = False

            def execute(self, sql, params=()):
                result = self._inner.execute(sql, params)
                if sql.lstrip().upper().startswith("INSERT INTO"):
                    self.inserted = True
                    return result
                if self.inserted and "FROM assessment_events" in sql:
                    values = list(result.fetchone())
                    columns = research_store_module._EVENT_PROJECTION_COLUMNS
                    values[columns.index("event_type")] = "score_snapshot_imported"
                    values[columns.index("created_at")] = "2026-09-01T00:00:00Z"
                    return _Tampered(values)
                return result

        drifted = _InsertRereadDrift(conn)
        exc = self._refused_projection(
            lambda: research_store_module.cas_processing_event(
                drifted, event_id=3, **kwargs
            )
        )
        self.assertIn("insert reread drifted", str(exc))
        self.assertIn("event_type", str(exc))
        row = conn.execute(
            "SELECT payload_json FROM assessment_events WHERE id=3"
        ).fetchone()
        self.assertEqual(row["payload_json"], "{}")

    def test_malformed_profile_ids_refuse_as_projection_conflict(self) -> None:
        conn = self._conn()
        for bad in ("bad", "", "prf_", "PRF_" + "a" * 32, "prf_" + "g" * 32):
            with self.subTest(profile_id=repr(bad)):
                self._refused_projection(
                    lambda b=bad: research_store_module.plan_accepted_score(
                        conn,
                        result=self._result(profile_id=b),
                        url="u", title="t", company="",
                        extraction_confidence=None,
                        accepted_at=self.TS,
                    )
                )
                self._refused_projection(
                    lambda b=bad: research_store_module.plan_processing_event(
                        conn,
                        profile_id=b,
                        job_key=self.K,
                        event_type="processing_score_accepted",
                        actor_kind="deterministic",
                        payload_json="{}",
                        idempotency_key="k",
                        created_at=self.TS,
                        event_id=70,
                    )
                )

    def test_sqlite_operational_errors_propagate_with_code(self) -> None:
        def coded(code, message):
            error = sqlite3.OperationalError(message)
            error.sqlite_errorcode = code
            error.sqlite_errorname = {sqlite3.SQLITE_BUSY: "SQLITE_BUSY",
                                      sqlite3.SQLITE_IOERR: "SQLITE_IOERR"}.get(code)
            return error

        class _Empty:
            def fetchone(self):
                return None

        class _InsertBusy:
            def execute(self, sql, params=()):
                if sql.lstrip().upper().startswith("INSERT INTO"):
                    raise coded(sqlite3.SQLITE_BUSY, "database is locked")
                return _Empty()

        with self.assertRaises(sqlite3.OperationalError) as busy_exc:
            research_store_module.cas_accepted_score(
                _InsertBusy(),
                result=self._result(),
                url="u", title="t", company="",
                extraction_confidence=None,
                accepted_at=self.TS,
            )
        self.assertEqual(busy_exc.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
        self.assertNotIsInstance(busy_exc.exception,
                                 research_store_module.ProjectionConflict)

        class _PlanIOErr:
            def __init__(self):
                self.calls = 0

            def execute(self, sql, params=()):
                self.calls += 1
                if "assessments" in sql:
                    raise coded(sqlite3.SQLITE_IOERR, "disk I/O error")
                raise AssertionError("unexpected statement")

        probe = _PlanIOErr()
        with self.assertRaises(sqlite3.OperationalError) as ioerr_exc:
            research_store_module.plan_accepted_score(
                probe,
                result=self._result(),
                url="u", title="t", company="",
                extraction_confidence=None,
                accepted_at=self.TS,
            )
        self.assertEqual(ioerr_exc.exception.sqlite_errorcode, sqlite3.SQLITE_IOERR)

        # Event reread boundary passthrough.
        store = self._store()
        writer = self._conn(store=store)
        self._seed_row(writer)
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )
        research_store_module.cas_processing_event(writer, event_id=1, **kwargs)
        writer.commit()

        class _RereadIOErr:
            def __init__(self, inner):
                self._inner = inner

            def execute(self, sql, params=()):
                if ("assessment_events" in sql
                        and sql.lstrip().upper().startswith("SELECT")
                        and "WHERE id=?" in sql):
                    raise coded(sqlite3.SQLITE_IOERR, "disk I/O error")
                return self._inner.execute(sql, params)

        drifted = _RereadIOErr(writer)
        with self.assertRaises(sqlite3.OperationalError) as reread_ioerr_exc:
            research_store_module.cas_processing_event(
                drifted, event_id=1, **kwargs
            )
        self.assertEqual(reread_ioerr_exc.exception.sqlite_errorcode,
                         sqlite3.SQLITE_IOERR)
        writer.close()

        class _EventPlanBusy:
            def execute(self, sql, params=()):
                if "assessment_events" in sql:
                    error = sqlite3.OperationalError("database is locked")
                    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                    raise error
                return _Empty()

        plan_busy_conn = _EventPlanBusy()
        with self.assertRaises(sqlite3.OperationalError) as event_plan_busy:
            research_store_module.plan_processing_event(
                plan_busy_conn,
                profile_id=self.PID,
                job_key=self.K,
                event_type="processing_score_accepted",
                actor_kind="deterministic",
                payload_json="{}",
                idempotency_key="k",
                created_at=self.TS,
                event_id=9,
            )
        self.assertEqual(event_plan_busy.exception.sqlite_errorcode,
                         sqlite3.SQLITE_BUSY)
        self.assertNotIsInstance(event_plan_busy.exception,
                                 research_store_module.ProjectionConflict)

    def test_real_busy_lock_propagates_not_conflict(self) -> None:
        store = self._store()
        holder = self._conn(store=store)
        holder.execute("PRAGMA busy_timeout=0")
        holder.execute("BEGIN IMMEDIATE")
        try:
            contender = sqlite3.connect(store.path, timeout=0)
            contender.execute("PRAGMA busy_timeout=0")
            self.addCleanup(contender.close)
            with self.assertRaises(sqlite3.OperationalError) as locked:
                contender.execute(
                    "INSERT INTO assessments(profile_id,job_key,url,title,"
                    "company,opportunity,fit,final_score,fit_status,"
                    "score_payload_json,score_payload_hash)"
                    " VALUES('prf_" + "b" * 32 + "','k','u','t','',"
                    "0.5,0.5,50,'uncalibrated','{}','" + "c" * 64 + "')"
                )
            self.assertEqual(locked.exception.sqlite_errorcode,
                             sqlite3.SQLITE_BUSY)
        finally:
            holder.rollback()
        self.assertNotIsInstance(locked.exception,
                                 research_store_module.ProjectionConflict)

    _KWARGS = dict(
        profile_id="prf_" + "a" * 32,
        job_key="boards.example:j-1",
        event_type="processing_score_accepted",
        actor_kind="deterministic",
        payload_json="{}",
        idempotency_key="processing-score:prf_" + "a" * 32 + ":abc",
        created_at="2026-08-25T12:00:00.000000+00:00",
    )

    def _seed_event_row(self, conn, event_id=1):
        self._seed_row(conn)
        kwargs = dict(self._KWARGS)
        conn.execute(
            f"""INSERT INTO assessment_events(
                 {','.join(research_store_module._EVENT_PROJECTION_COLUMNS)})
                 VALUES(?,?,?,?,?,?,?,?)""",
            (
                event_id,
                kwargs["profile_id"],
                kwargs["job_key"],
                kwargs["event_type"],
                kwargs["actor_kind"],
                kwargs["payload_json"],
                kwargs["idempotency_key"],
                kwargs["created_at"],
            ),
        )
        conn.commit()

    def test_plan_rejects_bool_and_malformed_via_custom_factories(self) -> None:
        store = self._store()
        bool_conn = sqlite3.connect(store.path)
        self.addCleanup(bool_conn.close)
        bool_conn.row_factory = (
            lambda cursor, row: [True if index == 0 else value
                                 for index, value in enumerate(row)]
        )
        self._seed_event_row(bool_conn, event_id=1)
        factory_before = bool_conn.row_factory
        exc = self._refused_projection(
            lambda: research_store_module.plan_processing_event(
                bool_conn, event_id=1,
                idempotency_key=self._KWARGS["idempotency_key"],
                **{k: v for k, v in self._KWARGS.items()
                   if k != "idempotency_key"},
            )
        )
        self.assertIn("stored id", str(exc))
        self.assertIs(bool_conn.row_factory, factory_before)

        ts_conn = sqlite3.connect(store.path)
        self.addCleanup(ts_conn.close)
        ts_conn.row_factory = (
            lambda cursor, row: ["oops" if index == 7 else value
                                 for index, value in enumerate(row)]
        )
        self._refused_projection(
            lambda: research_store_module.plan_processing_event(
                ts_conn, event_id=1,
                idempotency_key=self._KWARGS["idempotency_key"],
                **{k: v for k, v in self._KWARGS.items()
                   if k != "idempotency_key"},
            )
        )

    def test_row_and_tuple_factories_pass_exact_reuse(self) -> None:
        store = self._store()
        writer = self._conn(store=store)
        self._seed_event_row(writer, event_id=1)

        row_factory_conn = store.connect()  # store default is sqlite3.Row
        self.addCleanup(row_factory_conn.close)
        self.assertIs(row_factory_conn.row_factory, sqlite3.Row)
        before = row_factory_conn.total_changes
        outcome = research_store_module.cas_processing_event(
            row_factory_conn, event_id=1,
            idempotency_key=self._KWARGS["idempotency_key"],
            **{k: v for k, v in self._KWARGS.items()
               if k != "idempotency_key"},
        )
        self.assertEqual(outcome.action, "reuse")
        self.assertEqual(outcome.projection.event_id, 1)
        self.assertEqual(row_factory_conn.total_changes - before, 0)
        self.assertIs(row_factory_conn.row_factory, sqlite3.Row)

        tuple_conn = sqlite3.connect(store.path)
        self.addCleanup(tuple_conn.close)
        tuple_conn.execute("PRAGMA busy_timeout=250")
        self.assertIsNone(tuple_conn.row_factory)
        outcome = research_store_module.cas_processing_event(
            tuple_conn, event_id=1,
            idempotency_key=self._KWARGS["idempotency_key"],
            **{k: v for k, v in self._KWARGS.items()
               if k != "idempotency_key"},
        )
        self.assertEqual(outcome.action, "reuse")
        self.assertEqual(outcome.projection.created_at, self._KWARGS["created_at"])
        self.assertIsNone(tuple_conn.row_factory)

    def test_exact_numeric_primitive_and_bound_matrix(self) -> None:
        def plan_with(**overrides):
            conn = self._conn(store=self._store(unique=True))
            try:
                return research_store_module.plan_accepted_score(
                    conn,
                    result=self._result(
                        **{k: v for k, v in overrides.items()
                           if k != "extraction_confidence"}
                    ),
                    url="u", title="t", company="",
                    extraction_confidence=overrides.get(
                        "extraction_confidence"
                    ),
                    accepted_at=self.TS,
                )
            finally:
                conn.close()

        positive_cases = {
            "opportunity_low_int": {"opportunity": 0},
            "opportunity_high_float": {"opportunity": 1.0},
            "fit_low_int": {"fit": 0},
            "fit_high_float": {"fit": 1.0},
            "final_low_float": {"final": 0.0},
            "final_high_int": {"final": 100},
        }
        for label, overrides in positive_cases.items():
            with self.subTest(case=label):
                plan = plan_with(**overrides)
                self.assertEqual(plan.action, "insert")

        confidence_positives = {0: 0.0, 1: 1.0, 2: 0.85}
        for tag, value in confidence_positives.items():
            with self.subTest(confidence=value):
                plan = plan_with(extraction_confidence=value)
                self.assertEqual(plan.action, "insert")
                if tag == 2:
                    self.assertEqual(plan.insert.extraction_confidence, 0.85)

        negative_cases = {
            "opportunity_below": {"opportunity": -0.1},
            "opportunity_above": {"opportunity": 1.5},
            "fit_below": {"fit": -1},
            "fit_above": {"fit": 1.0001},
            "final_below": {"final": -0.5},
            "final_above": {"final": 101},
            "fit_bool": {"fit": True},
            "fit_nan": {"fit": float("nan")},
            "fit_absurd_int": {"fit": 10 ** 400},
        }
        for label, overrides in negative_cases.items():
            with self.subTest(case=label):
                self._refused_projection(lambda o=overrides: plan_with(**o))

        for bad in (-0.5, 1.5, True):
            with self.subTest(confidence=repr(bad)):
                self._refused_projection(
                    lambda b=bad: plan_with(extraction_confidence=b)
                )

    @staticmethod
    def _dict_factory(cursor, row):
        return {description[0]: value
                for description, value in zip(cursor.description, row)}

    class _ShapeProxy:
        """Returns a crafted object for the targeted SELECT family."""

        def __init__(self, inner, marker, craft):
            self._inner = inner
            self._marker = marker
            self._craft = craft
            self.calls = 0

        def execute(self, sql, params=()):
            result = self._inner.execute(sql, params)
            if sql.lstrip().upper().startswith("SELECT") and self._marker in sql:
                self.calls += 1
                return self._craft(result)
            return result

    def test_dict_factory_cas_reuse_exact_for_score_and_event(self) -> None:

        store = self._store()
        writer = self._conn(store=store)
        result = self._result()
        _, digest = research_store_module.canonical_score_payload(result)
        self._seed_row(writer)
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )
        research_store_module.cas_processing_event(writer, event_id=1, **kwargs)
        writer.commit()

        # Independent tuple connection reads the durable truth.
        truth = sqlite3.connect(store.path)
        truth.row_factory = sqlite3.Row
        self.addCleanup(truth.close)
        score_row = truth.execute(
            "SELECT * FROM assessments WHERE profile_id=? AND job_key=?",
            (self.PID, self.K),
        ).fetchone()
        event_row = truth.execute(
            "SELECT * FROM assessment_events WHERE id=1"
        ).fetchone()
        truth.close()

        def open_reader():
            conn = sqlite3.connect(store.path)
            conn.execute("PRAGMA busy_timeout=250")
            conn.row_factory = self._dict_factory
            self.addCleanup(conn.close)
            return conn

        expected_score = {
            column: score_row[column]
            for column in research_store_module._SCORE_PROJECTION_COLUMNS
        }
        score_conn = open_reader()
        identity_before = score_conn.row_factory
        before = score_conn.total_changes
        outcome = research_store_module.cas_accepted_score(
            score_conn,
            result=result,
            url="https://boards.example/listing/j-1",
            title="Senior Backend Engineer",
            company="",
            extraction_confidence=0.9,
            accepted_at=self.TS,
        )
        self.assertEqual(outcome.action, "reuse")
        self.assertEqual(score_conn.total_changes - before, 0)
        self.assertIs(score_conn.row_factory, identity_before)
        self.assertEqual(
            dataclasses.asdict(outcome.projection), expected_score
        )

        expected_event = {
            "event_id": event_row["id"],
            "profile_id": event_row["profile_id"],
            "job_key": event_row["job_key"],
            "event_type": event_row["event_type"],
            "actor_kind": event_row["actor_kind"],
            "payload_json": event_row["payload_json"],
            "idempotency_key": event_row["idempotency_key"],
            "created_at": event_row["created_at"],
        }
        event_conn = open_reader()
        identity_before = event_conn.row_factory
        before = event_conn.total_changes
        outcome = research_store_module.cas_processing_event(
            event_conn, event_id=1, **kwargs
        )
        self.assertEqual(outcome.action, "reuse")
        self.assertEqual(event_conn.total_changes - before, 0)
        self.assertIs(event_conn.row_factory, identity_before)
        self.assertEqual(
            dataclasses.asdict(outcome.projection), expected_event
        )
    def test_malformed_row_shapes_conflict_on_both_families(self) -> None:
        store = self._store()
        writer = self._conn(store=store)
        self._seed_row(writer)
        writer.commit()
        writer.close()

        score_columns = research_store_module._SCORE_ROW_COLUMNS
        score_good = [
            self.PID, self.K, "u", "t", "", 0.555, 0.42, 48.75,
            "uncalibrated", 0.9, "{}", "a" * 64, "scored", self.TS, self.TS,
            None, None, None,
        ]
        event_columns = research_store_module._EVENT_PROJECTION_COLUMNS
        event_good = [
            1, self.PID, self.K, "processing_score_accepted",
            "deterministic", "{}", "processing-score:" + self.PID + ":abc",
            self.TS,
        ]

        class _Payload:
            def __init__(self, payload):
                self._payload = payload

            def fetchone(self):
                return self._payload

            def fetchall(self):
                return [self._payload]

        class _Craft:
            def __init__(self, make):
                self.make = make

            def __call__(self, result):
                return _Payload(self.make(result.fetchone()))

        def make_family_shapes(columns, drop_column):
            def mapping_missing(row, columns=columns, drop_column=drop_column):
                data = {c: v for c, v in zip(columns, list(row))}
                data.pop(drop_column)
                return data

            def mapping_extra(row, columns=columns):
                data = {c: v for c, v in zip(columns, list(row))}
                data["ghost"] = 1
                return data

            def mapping_nonstring_keys(row, columns=columns):
                return {index: index for index in range(len(columns))}

            def sequence_short(row, columns=columns):
                return [0] * (len(columns) - 1)

            def string_row(_row, _columns=None):
                return "x" * 40

            def bytes_row(_row, _columns=None):
                return b"\x00" * 40

            return {
                "mapping_missing_key": mapping_missing,
                "mapping_extra_key": mapping_extra,
                "mapping_nonstring_keys": mapping_nonstring_keys,
                "sequence_short": sequence_short,
                "string_row": string_row,
                "bytes_row": bytes_row,
            }
        families = {
            "score": {
                "columns": score_columns,
                "good": score_good,
                "marker": "FROM assessments WHERE profile_id",
                "drop_column": "state",
                "call": lambda proxy: research_store_module.plan_accepted_score(
                    proxy,
                    result=self._result(),
                    url="https://boards.example/listing/j-1",
                    title="Senior Backend Engineer",
                    company="",
                    extraction_confidence=0.9,
                    accepted_at=self.TS,
                ),
            },
            "event": {
                "columns": event_columns,
                "good": event_good,
                "marker": "assessment_events",
                "drop_column": "actor_kind",
                "call": lambda proxy: (
                    research_store_module.plan_processing_event(
                        proxy,
                        profile_id=self.PID,
                        job_key=self.K,
                        event_type="processing_score_accepted",
                        actor_kind="deterministic",
                        payload_json="{}",
                        idempotency_key="processing-score:" + self.PID + ":abc",
                        created_at=self.TS,
                        event_id=5,
                    )
                ),
            },
        }

        # Seed the event family so classification reaches the one-row branch.
        uq_store = self._store(unique=True)
        seed_conn = self._conn(store=uq_store)
        self._seed_event_row(seed_conn, event_id=1)
        seed_conn.commit()
        seed_conn.close()

        for family_name, spec in families.items():
            family_shapes = make_family_shapes(
                spec["columns"], spec["drop_column"]
            )
            for shape_label, make in family_shapes.items():
                with self.subTest(family=family_name, shape=shape_label):
                    conn = self._conn(
                        store=store if family_name == "score" else uq_store
                    )
                    try:
                        def craft(result, make=make, columns=spec["columns"]):
                            row = result.fetchone()
                            if row is None:
                                return _Payload([])
                            payload = make(row, columns)
                            return _Payload(payload)

                        proxy = self._ShapeProxy(conn, spec["marker"], craft)
                        exc = self._refused_projection(lambda pr=proxy: spec["call"](pr))
                        self.assertIn("malformed stored row", str(exc))
                        self.assertGreaterEqual(proxy.calls, 1)
                    finally:
                        conn.close()


    def test_event_malformed_field_yields_single_diagnostic(self) -> None:
        good = {
            "id": 1,
            "profile_id": self.PID,
            "job_key": self.K,
            "event_type": "processing_score_accepted",
            "actor_kind": "deterministic",
            "payload_json": "{}",
            "idempotency_key": "k",
            "created_at": self.TS,
        }
        variants = {
            "created_at_bad_lexical": {**good, "created_at": "oops"},
            "actor_kind_non_string": {**good, "actor_kind": 7},
            "id_bool": {**good, "id": True},
        }
        for label, values in variants.items():
            with self.subTest(case=label):
                problems = research_store_module._event_row_problems(
                    values, dict(good)
                )
                self.assertEqual(len(problems), 1, problems)

        nonexact = {**good, "payload_json": '{"x":1}'}
        problems = research_store_module._event_row_problems(
            nonexact, dict(good)
        )
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("payload_json differs", problems[0])

    def _identity_tamper_proxy(self, conn, field, occurrence):
        """Cursor wrapper tampering exactly one identity field once."""

        columns = research_store_module._SCORE_ROW_COLUMNS
        marker = "FROM assessments WHERE profile_id"
        state = {"seen": 0, "invoked": False}

        class Cursor:
            def __init__(self, payload):
                self._payload = payload

            def fetchone(self):
                return self._payload

            def fetchall(self):
                return [self._payload]

        class Connection:
            def execute(self, sql, params=()):
                result = conn.execute(sql, params)
                if (sql.lstrip().upper().startswith("SELECT")
                        and marker in sql):
                    state["seen"] += 1
                    if state["seen"] == occurrence:
                        state["invoked"] = True
                        row = result.fetchone()
                        data = {
                            column: value
                            for column, value in zip(columns, list(row))
                        }
                        data[field] = (
                            "prf_" + "b" * 32
                            if field == "profile_id"
                            else "other.example:j-1"
                        )
                        return Cursor(data)
                return result

        return Connection(), state

    def test_score_identity_only_substitutions_plan_and_reread(self) -> None:
        store = self._store()
        writer = self._conn(store=store)
        self._seed_row(writer)
        writer.commit()

        call_kwargs = dict(
            result=self._result(),
            url="https://boards.example/listing/j-1",
            title="Senior Backend Engineer",
            company="",
            extraction_confidence=0.9,
            accepted_at=self.TS,
        )
        for field in ("profile_id", "job_key"):
            with self.subTest(boundary="plan", field=field):
                reader = self._conn(store=store)
                try:
                    proxy, state = self._identity_tamper_proxy(reader, field, 1)
                    exc = self._refused_projection(
                        lambda pr=proxy: research_store_module.cas_accepted_score(
                            pr, **call_kwargs
                        )
                    )
                    self.assertTrue(state["invoked"])
                    self.assertIn(
                        f"stored {field} differs from the accepted score",
                        str(exc),
                    )
                finally:
                    reader.close()

        for field in ("profile_id", "job_key"):
            with self.subTest(boundary="reread", field=field):
                reader = self._conn(store=store)
                try:
                    proxy, state = self._identity_tamper_proxy(reader, field, 2)
                    exc = self._refused_projection(
                        lambda pr=proxy: research_store_module.cas_accepted_score(
                            pr, **call_kwargs
                        )
                    )
                    self.assertTrue(state["invoked"])
                    self.assertIn(
                        f"stored {field} differs from the accepted score",
                        str(exc),
                    )
                finally:
                    reader.close()

    def test_invalid_fit_status_primitive_refused_before_first_select(self) -> None:
        class Exploding:
            touched = False

            def execute(self, sql, params=()):
                type(self).touched = True
                raise AssertionError("first SELECT reached")

        bad_result = dataclasses.replace(
            self._result(), fit_status="uncalibrated"
        )
        connection = Exploding()
        self._refused_projection(
            lambda: research_store_module.cas_accepted_score(
                connection,
                result=bad_result,
                url="u", title="t", company="",
                extraction_confidence=None,
                accepted_at=self.TS,
            ),
            fragment="fit_status",
        )
        self.assertFalse(Exploding.touched)

    def test_sibling_rows_are_untouched_by_cas(self) -> None:
        conn = self._conn()
        self._seed_row(conn, key=self.K2)
        sibling_before = conn.execute(
            "SELECT * FROM assessments WHERE job_key=?", (self.K2,)
        ).fetchone()
        research_store_module.cas_accepted_score(
            conn,
            result=self._result(),
            url="https://x",
            title="t",
            company="",
            extraction_confidence=0.9,
            accepted_at=self.TS,
        )
        sibling_after = conn.execute(
            "SELECT * FROM assessments WHERE job_key=?", (self.K2,)
        ).fetchone()
        self.assertEqual(tuple(sibling_before), tuple(sibling_after))

    # ------------------------------------------------------- event plans

    def test_event_insert_lastrowid_exact_and_reread(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        plan = research_store_module.plan_processing_event(
            conn,
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
            event_id=7,
        )
        self.assertEqual(plan.action, "insert")
        projection = research_store_module.execute_processing_event_insert(
            conn, plan.insert
        )
        self.assertEqual(projection.event_id, 7)
        self.assertEqual(projection.created_at, self.TS)
        row = conn.execute(
            "SELECT * FROM assessment_events WHERE id=7"
        ).fetchone()
        self.assertEqual(row["event_type"], "processing_score_accepted")

    def test_event_reuse_is_zero_dml_and_mismatch_conflicts(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )
        outcome = research_store_module.cas_processing_event(
            conn, event_id=3, **kwargs
        )
        self.assertEqual(outcome.action, "insert")
        self.assertEqual(outcome.projection.event_id, 3)
        before = conn.total_changes
        plan = research_store_module.plan_processing_event(conn, event_id=3, **kwargs)
        self.assertEqual(plan.action, "reuse")
        self.assertEqual(plan.reused_event_id, 3)
        self.assertEqual(conn.total_changes - before, 0)
        # Every field participates in exact reuse comparison, including the
        # supplied event id itself.
        for field, value in (
            ("event_id", 9),
            ("payload_json", '{"x":1}'),
            ("idempotency_key", "other-key"),
            ("actor_kind", "external"),
            ("created_at", "2026-08-27T00:00:00Z"),
        ):
            with self.subTest(field=field):
                mutated = dict(kwargs, event_id=3)
                mutated[field] = value
                self._refused_projection(
                    lambda m=mutated: research_store_module.plan_processing_event(
                        conn, **m
                    )
                )
        with self.subTest(field="profile_id"):
            self._refused_projection(
                lambda: research_store_module.cas_processing_event(
                    conn,
                    event_id=40,
                    profile_id="prf_" + "f" * 32,
                    job_key=self.K,
                    event_type="processing_score_accepted",
                    actor_kind="deterministic",
                    payload_json="{}",
                    idempotency_key="processing-score:" + self.PID + ":abc",
                    created_at=self.TS,
                )
            )

    def test_event_type_and_actor_are_exact(self) -> None:
        conn = self._conn()
        base = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="k",
            created_at=self.TS,
            event_id=50,
        )
        for field, value in (
            ("event_type", "score_snapshot_imported"),
            ("actor_kind", "probabilistic"),
        ):
            with self.subTest(field=field):
                self._refused_projection(
                    lambda f=field, v=value: research_store_module.plan_processing_event(
                        conn, **{**base, f: v}
                    )
                )

    def test_multiple_matching_events_conflict(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        for event_id in (20, 21):
            conn.execute(
                """INSERT INTO assessment_events(id,profile_id,job_key,event_type,
                   actor_kind,payload_json,idempotency_key,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    event_id, self.PID, self.K, "processing_score_accepted",
                    "deterministic", "{}", f"key-{event_id}", self.TS,
                ),
            )
        self._refused_projection(
            lambda: research_store_module.plan_processing_event(
                conn,
                profile_id=self.PID,
                job_key=self.K,
                event_type="processing_score_accepted",
                actor_kind="deterministic",
                payload_json="{}",
                idempotency_key="k",
                created_at=self.TS,
                event_id=22,
            )
        )

    def test_event_bounds_and_timestamp_validation(self) -> None:
        conn = self._conn()
        self._seed_row(conn)
        base = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="k",
            created_at=self.TS,
        )
        for bad_id in (0, -1, 2**63, True, "7"):
            with self.subTest(event_id=bad_id):
                self._refused_projection(
                    lambda b=base, i=bad_id: research_store_module.plan_processing_event(
                        conn, event_id=i, **b
                    )
                )
        long_key = "a" * 513
        self._refused_projection(
            lambda: research_store_module.plan_processing_event(
                conn, event_id=30, idempotency_key=long_key, **{
                    k: v for k, v in base.items() if k != "idempotency_key"
                }
            )
        )
        self._refused_projection(
            lambda: research_store_module.plan_processing_event(
                conn, event_id=31, idempotency_key="caf\u00e9-key", **{
                    k: v for k, v in base.items() if k != "idempotency_key"
                }
            )
        )
        naive = dict(base, created_at="2026-08-25T12:00:00")
        self._refused_projection(
            lambda: research_store_module.plan_processing_event(
                conn, event_id=32, **naive
            )
        )
        self._refused_projection(
            lambda: research_store_module.plan_accepted_score(
                conn,
                result=self._result(),
                url="u", title="t", company="",
                extraction_confidence=None,
                accepted_at="2026-08-25T12:00:00",
            )
        )


class StageDPart3C1AClassificationTests(
    StageDPart3C1AssessmentCasTests
):
    """C1A: presence/authority classifiers over caller-owned connections."""

    def test_score_absent_classifies_insert_required(self) -> None:
        conn = self._conn()
        before = conn.total_changes
        classification = research_store_module.classify_accepted_score(
            conn,
            result=self._result(),
            url="https://x", title="t", company="",
            extraction_confidence=0.9,
        )
        self.assertEqual(classification.action, "insert_required")
        self.assertIsNone(classification.projection)
        self.assertEqual(conn.total_changes - before, 0)

    def test_score_exact_reuse_preserves_unequal_timestamps(self) -> None:
        conn = self._conn()
        self._seed_row(
            conn, created_at=self.TS, updated_at="2026-08-26T00:00:00Z"
        )
        before = conn.total_changes
        classification = research_store_module.classify_accepted_score(
            conn,
            result=self._result(),
            url="https://boards.example/listing/j-1",
            title="Senior Backend Engineer",
            company="",
            extraction_confidence=0.9,
        )
        self.assertEqual(classification.action, "reuse")
        projection = classification.projection
        self.assertEqual(projection.created_at, self.TS)
        self.assertEqual(projection.updated_at, "2026-08-26T00:00:00Z")
        self.assertNotEqual(projection.created_at, projection.updated_at)
        self.assertEqual(conn.total_changes - before, 0)

    def test_every_score_substitution_conflicts_via_classifier(self) -> None:
        overrides = {
            "url": "https://other",
            "title": "Other",
            "company": "OtherCo",
            "opportunity": 0.554,
            "fit": 0.421,
            "final_score": 48.74,
            "extraction_confidence": 0.5,
            "score_payload_json": "{}",
            "score_payload_hash": "a" * 64,
            "state": "employer_researched",
            "opportunity_decision": "pass",
            "opportunity_reason": "why",
            "policy_hash": "b" * 64,
            "created_at": "not-a-timestamp",
            "updated_at": "2026-13-01T00:00:00Z",
            "profile_id": "prf_" + "b" * 32,
            "job_key": "other.example:j-1",
        }
        identity_columns = ("profile_id", "job_key")
        for column, value in overrides.items():
            with self.subTest(column=column):
                conn = self._conn(store=self._store(unique=True))
                try:
                    if column in identity_columns:
                        # Primary-key identity substitution makes the whole
                        # row family absent: classification must report
                        # insert_required rather than conflict.
                        self._seed_row(conn, **{column: value})
                        classification = (
                            research_store_module.classify_accepted_score(
                                conn,
                                result=self._result(),
                                url="https://boards.example/listing/j-1",
                                title="Senior Backend Engineer",
                                company="",
                                extraction_confidence=0.9,
                            )
                        )
                        self.assertEqual(
                            classification.action, "insert_required"
                        )
                        continue
                    self._seed_row(conn, **{column: value})
                    self._refused_projection(
                        lambda c=conn:
                            research_store_module.classify_accepted_score(
                                c,
                                result=self._result(),
                                url="https://boards.example/listing/j-1",
                                title="Senior Backend Engineer",
                                company="",
                                extraction_confidence=0.9,
                            )
                    )
                finally:
                    conn.close()

    def test_row_factories_exact_and_untouched_for_classifier(self) -> None:
        store = self._store()
        writer = self._conn(store=store)
        self._seed_event_row(writer, event_id=1)
        writer.commit()
        writer.close()
        factories = {
            "row": sqlite3.Row,
            "tuple": None,
            "dict": lambda cursor, row: {
                d[0]: v for d, v in zip(cursor.description, row)
            },
        }
        for label, factory in factories.items():
            with self.subTest(factory=label):
                conn = sqlite3.connect(store.path)
                conn.execute("PRAGMA busy_timeout=250")
                conn.row_factory = factory
                self.addCleanup(conn.close)
                identity_before = conn.row_factory
                classification = (
                    research_store_module.classify_accepted_score(
                        conn,
                        result=self._result(),
                        url="https://boards.example/listing/j-1",
                        title="Senior Backend Engineer",
                        company="",
                        extraction_confidence=0.9,
                    )
                )
                self.assertEqual(classification.action, "reuse")
                event_classification = (
                    research_store_module.classify_processing_score_event(
                        conn, profile_id=self.PID, job_key=self.K
                    )
                )
                self.assertEqual(
                    (event_classification.action, event_classification.count),
                    ("existing", 1),
                )
                self.assertIs(conn.row_factory, identity_before)

    def test_event_presence_zero_one_multiple_never_authenticates(self) -> None:
        conn = self._conn(store=self._store(unique=True))
        kwargs = dict(
            profile_id=self.PID,
            job_key=self.K,
            event_type="processing_score_accepted",
            actor_kind="deterministic",
            payload_json="{}",
            idempotency_key="processing-score:" + self.PID + ":abc",
            created_at=self.TS,
        )
        empty = research_store_module.classify_processing_score_event(
            conn, profile_id=self.PID, job_key=self.K
        )
        self.assertEqual((empty.action, empty.count), ("insert_required", 0))
        self._seed_row(conn)
        research_store_module.cas_processing_event(conn, event_id=1, **kwargs)
        one = research_store_module.classify_processing_score_event(
            conn, profile_id=self.PID, job_key=self.K
        )
        self.assertEqual((one.action, one.count), ("existing", 1))
        # Arbitrary content is never authenticated or reused: the public
        # CAS refuses any changed field against the existing row.
        arbitrary = dict(kwargs, payload_json='{"z":9}',
                         idempotency_key="other-key")
        self._refused_projection(
            lambda: research_store_module.cas_processing_event(
                conn, event_id=3, **arbitrary
            )
        )
        # Fixture-level second row (direct SQL) proves presence counting.
        conn.execute(
            f"""INSERT INTO assessment_events(
                 {','.join(research_store_module._EVENT_PROJECTION_COLUMNS)})
                 VALUES(?,?,?,?,?,?,?,?)""",
            (
                2, self.PID, self.K, "processing_score_accepted",
                "deterministic", '{"z":9}', "other-key", self.TS,
            ),
        )
        conn.commit()
        many = research_store_module.classify_processing_score_event(
            conn, profile_id=self.PID, job_key=self.K
        )
        self.assertEqual((many.action, many.count), ("existing", 2))

    def test_event_malformed_shapes_refuse_classification(self) -> None:
        store = self._store()
        writer = self._conn(store=store)
        self._seed_event_row(writer, event_id=1)
        writer.commit()
        writer.close()
        columns = research_store_module._EVENT_PROJECTION_COLUMNS

        class _Payload:
            def __init__(self, payload):
                self._payload = payload

            def fetchone(self):
                return self._payload

            def fetchall(self):
                return [self._payload]

        def mapping_missing(row):
            data = {c: v for c, v in zip(columns, list(row))}
            data.pop("actor_kind")
            return data

        def mapping_extra(row):
            data = {c: v for c, v in zip(columns, list(row))}
            data["ghost"] = 1
            return data

        shapes = {
            "mapping_missing": mapping_missing,
            "mapping_extra": mapping_extra,
            "sequence_short": lambda row: list(row)[:-1],
        }
        for label, make in shapes.items():
            with self.subTest(shape=label):
                conn = self._conn(store=store)
                try:
                    def craft(result, make=make):
                        row = result.fetchone()
                        return _Payload(make(row))

                    class _ShapeProxy:
                        def execute(self, sql, params=()):
                            result = conn.execute(sql, params)
                            if sql.lstrip().upper().startswith("SELECT"):
                                return craft(result)
                            return result

                    proxy = _ShapeProxy()
                    self._refused_projection(
                        lambda pr=proxy:
                            research_store_module.classify_processing_score_event(
                                pr,
                                profile_id=self.PID,
                                job_key=self.K,
                            )
                    )
                finally:
                    conn.close()

    def test_score_identity_proxy_substitutions_conflict(self) -> None:
        """Returned-row identity drift conflicts even though the SELECT
        still targets the expected primary-key family."""

        store = self._store()
        writer = self._conn(store=store)
        self._seed_row(writer)
        writer.commit()
        columns = research_store_module._SCORE_ROW_COLUMNS

        class _Payload:
            def __init__(self, payload):
                self._payload = payload

            def fetchone(self):
                return self._payload

            def fetchall(self):
                return [self._payload]

        for field in ("profile_id", "job_key"):
            with self.subTest(field=field):
                conn = self._conn(store=store)
                try:
                    calls = {"n": 0}

                    class _Proxy:
                        def execute(self, sql, params=()):
                            result = conn.execute(sql, params)
                            if (sql.lstrip().upper().startswith("SELECT")
                                    and "assessments" in sql):
                                calls["n"] += 1
                                row = result.fetchone()
                                data = {
                                    c: v for c, v in zip(columns, list(row))
                                }
                                data[field] = (
                                    "prf_" + "b" * 32
                                    if field == "profile_id"
                                    else "other.example:j-1"
                                )
                                return _Payload(data)
                            return result

                    exc = self._refused_projection(
                        lambda pr=_Proxy():
                            research_store_module.classify_accepted_score(
                                pr,
                                result=self._result(),
                                url="https://boards.example/listing/j-1",
                                title="Senior Backend Engineer",
                                company="",
                                extraction_confidence=0.9,
                            )
                    )
                    self.assertGreaterEqual(calls["n"], 1)
                    self.assertIn(
                        f"stored {field} differs from the accepted score",
                        str(exc),
                    )
                finally:
                    conn.close()

    def test_classify_accepted_score_malformed_shapes_conflict(self) -> None:
        store = self._store()
        writer = self._conn(store=store)
        self._seed_row(writer)
        writer.commit()
        columns = research_store_module._SCORE_ROW_COLUMNS

        class _Payload:
            def __init__(self, payload):
                self._payload = payload

            def fetchone(self):
                return self._payload

            def fetchall(self):
                return [self._payload]

        def mapping_missing(row):
            data = {c: v for c, v in zip(columns, list(row))}
            data.pop("state")
            return data

        def mapping_extra(row):
            data = {c: v for c, v in zip(columns, list(row))}
            data["ghost"] = 1
            return data

        shapes = {
            "mapping_missing": mapping_missing,
            "mapping_extra": mapping_extra,
            "sequence_short": lambda row: list(row)[:-1],
        }
        for label, make in shapes.items():
            with self.subTest(shape=label):
                conn = self._conn(store=store)
                try:
                    class _Proxy:
                        def execute(self, sql, params=()):
                            result = conn.execute(sql, params)
                            if (sql.lstrip().upper().startswith("SELECT")
                                    and "assessments" in sql):
                                row = result.fetchone()
                                return _Payload(make(row))
                            return result

                    self._refused_projection(
                        lambda pr=_Proxy():
                            research_store_module.classify_accepted_score(
                                pr,
                                result=self._result(),
                                url="u", title="t", company="",
                                extraction_confidence=None,
                            )
                    )
                finally:
                    conn.close()

    def test_pre_sql_invalid_identity_never_touches_sql(self) -> None:
        class Exploding:
            touched = False

            def execute(self, sql, params=()):
                type(self).touched = True
                raise AssertionError("SQL reached")

        connection = Exploding()
        for bad_profile in (" bad", 5):
            with self.subTest(profile=repr(bad_profile)):
                self._refused_projection(
                    lambda b=bad_profile:
                        research_store_module.classify_accepted_score(
                            connection,
                            result=self._result(profile_id=b),
                            url="u", title="t", company="",
                            extraction_confidence=None,
                        )
                )
                self._refused_projection(
                    lambda b=bad_profile:
                        research_store_module.classify_processing_score_event(
                            connection, profile_id=b, job_key=self.K
                        )
                )
        self.assertFalse(Exploding.touched)
        short_result = dataclasses.replace(self._result(), job_key="x")
        self._refused_projection(
            lambda: research_store_module.classify_accepted_score(
                connection,
                result=short_result,
                url="u", title="t", company="",
                extraction_confidence=None,
            )
        )
        self.assertFalse(Exploding.touched)
        self._refused_projection(
            lambda: research_store_module.classify_processing_score_event(
                connection, profile_id=self.PID, job_key="x"
            )
        )
        self.assertFalse(Exploding.touched)

    def test_busy_ioerr_propagate_through_both_classifiers(self) -> None:
        def coded(code):
            error = sqlite3.OperationalError("injected")
            error.sqlite_errorcode = code
            return error

        class _FailSelect:
            def __init__(self, code):
                self.code = code

            def execute(self, sql, params=()):
                if sql.lstrip().upper().startswith("SELECT"):
                    raise coded(self.code)
                raise AssertionError("unexpected statement")

        for code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_IOERR):
            with self.subTest(code=code):
                probe = _FailSelect(code)
                with self.assertRaises(sqlite3.OperationalError) as raised:
                    research_store_module.classify_accepted_score(
                        probe,
                        result=self._result(),
                        url="u", title="t", company="",
                        extraction_confidence=None,
                    )
                self.assertEqual(
                    raised.exception.sqlite_errorcode, code
                )
                self.assertNotIsInstance(
                    raised.exception, research_store_module.ProjectionConflict
                )
                probe2 = _FailSelect(code)
                with self.assertRaises(sqlite3.OperationalError) as raised2:
                    research_store_module.classify_processing_score_event(
                        probe2, profile_id=self.PID, job_key=self.K
                    )
                self.assertEqual(
                    raised2.exception.sqlite_errorcode, code
                )

    def test_classifications_leave_total_changes_untouched(self) -> None:
        conn = self._conn()
        before = conn.total_changes
        research_store_module.classify_accepted_score(
            conn,
            result=self._result(),
            url="https://x", title="t", company="",
            extraction_confidence=None,
        )
        research_store_module.classify_processing_score_event(
            conn, profile_id=self.PID, job_key=self.K
        )
        self.assertEqual(conn.total_changes - before, 0)

    def test_static_classifier_sources_are_write_free(self) -> None:
        import inspect

        forbidden = (
            "INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ",
            "BEGIN ", "COMMIT", "ROLLBACK", "executescript",
            "sqlite3.connect(", "PRAGMA journal_mode",
        )
        for helper in (
            research_store_module.classify_accepted_score,
            research_store_module.classify_processing_score_event,
        ):
            source = inspect.getsource(helper)
            for token in forbidden:
                self.assertNotIn(token, source)




class StageDPart3C2AParserTests(unittest.TestCase):
    """Pure rollback-journal grammar primitives (no filesystem)."""

    MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

    def _make_header(self, *, n_rec=3, checksum_init=0xABCDEF01,
                     db_size=16, sector=4096, page=4096):
        h = self.MAGIC
        h += n_rec.to_bytes(4, "big")
        h += checksum_init.to_bytes(4, "big")
        h += db_size.to_bytes(4, "big")
        h += sector.to_bytes(4, "big")
        h += page.to_bytes(4, "big")
        return h

    def test_exact_field_offsets_and_endian(self):
        hdr = self._make_header(n_rec=42, checksum_init=0xDEADBEEF,
                                db_size=256, sector=8192, page=16384)
        result = processing_module._parse_rollback_header(hdr, file_size=65536)
        self.assertTrue(result.candidate)
        self.assertEqual(result.n_rec, 42)
        self.assertEqual(result.checksum_init, 0xDEADBEEF)
        self.assertEqual(result.initial_db_size, 256)
        self.assertEqual(result.sector_size, 8192)
        self.assertEqual(result.page_size, 16384)

    def test_file_size_512_is_not_candidate(self):
        hdr = self._make_header()
        r = processing_module._parse_rollback_header(hdr, file_size=512)
        self.assertFalse(r.candidate)

    def test_file_size_513_is_candidate(self):
        hdr = self._make_header()
        r = processing_module._parse_rollback_header(hdr, file_size=513)
        self.assertTrue(r.candidate)

    def test_absent_magic_not_candidate(self):
        hdr = b"\x00" * 28
        r = processing_module._parse_rollback_header(hdr, file_size=1024)
        self.assertFalse(r.candidate)

    def test_truncated_header_not_candidate(self):
        r = processing_module._parse_rollback_header(
            b"\xd9\xd5", file_size=1024)
        self.assertFalse(r.candidate)

    def test_sector_page_pow2_bounds(self):
        for bad_sector in (0, 100, 256, 131072):
            with self.subTest(sector=bad_sector):
                hdr = self._make_header(sector=bad_sector)
                r = processing_module._parse_rollback_header(
                    hdr, file_size=65536)
                self.assertFalse(r.candidate)
        for good_sector in (512, 1024, 4096, 65536):
            with self.subTest(sector=good_sector):
                hdr = self._make_header(sector=good_sector)
                r = processing_module._parse_rollback_header(
                    hdr, file_size=65536)
                self.assertTrue(r.candidate)

    def test_checksum_signed_bytes_ge128(self):
        path = bytes([200, 210, 220])  # all >= 128 => negative signed
        checksum = processing_module._sqlite_master_checksum(path)
        expected = ((-56) + (-46) + (-36)) % (2**32)
        self.assertEqual(checksum, expected)

    def test_checksum_positive_bytes(self):
        path = bytes([1, 2, 3])
        checksum = processing_module._sqlite_master_checksum(path)
        self.assertEqual(checksum, 6)

    def _make_tail(self, pathname_len, magic=None):
        if magic is None:
            magic = self.MAGIC
        return (
            pathname_len.to_bytes(4, "big")
            + b"\x00" * 4
            + magic
        )

    def _make_special_and_path(self, path: bytes) -> bytes:
        sj_pgno = (0x40000000 // 4096) + 1
        return sj_pgno.to_bytes(4, "big") + path

    def _assert_reason15(self, callable_, fragment=None):
        with self.assertRaises(processing_module.ProcessingRefused) as ctx:
            callable_()
        self.assertEqual(
            ctx.exception.reason,
            processing_module.REASON_ATOMIC_MODE,
        )
        if fragment:
            self.assertIn(fragment, str(ctx.exception))

    def test_header_page_sizes_good(self):
        for page in (512, 1024, 4096, 65536):
            with self.subTest(page=page):
                hdr = self._make_header(page=page)
                r = processing_module._parse_rollback_header(hdr, file_size=65536)
                self.assertTrue(r.candidate)

    def test_header_page_sizes_bad(self):
        for page in (0, 256, 1000, 131072):
            with self.subTest(page=page):
                hdr = self._make_header(page=page)
                r = processing_module._parse_rollback_header(hdr, file_size=65536)
                self.assertFalse(r.candidate)

    def test_header_sector_sizes_good(self):
        for sector in (512, 1024, 4096, 65536):
            with self.subTest(sector=sector):
                hdr = self._make_header(sector=sector)
                r = processing_module._parse_rollback_header(hdr, file_size=65536)
                self.assertTrue(r.candidate)

    def test_header_sector_sizes_bad(self):
        for sector in (0, 256, 1000, 131072):
            with self.subTest(sector=sector):
                hdr = self._make_header(sector=sector)
                r = processing_module._parse_rollback_header(hdr, file_size=65536)
                self.assertFalse(r.candidate)

    def _assert_reason15(self, callable_, fragment=None):
        with self.assertRaises(processing_module.ProcessingRefused) as ctx:
            callable_()
        self.assertEqual(
            ctx.exception.reason,
            processing_module.REASON_ATOMIC_MODE,
        )
        if fragment:
            self.assertIn(fragment, str(ctx.exception))

    def test_tail16_length_15_reason15(self):
        self._assert_reason15(
            lambda: processing_module._parse_master_pointer(
                journal_size=1000, page_size=4096, path_max=512,
                tail16=b'\x00' * 15, special_and_path=b'\x00' * 14))

    def test_tail16_length_17_reason15(self):
        self._assert_reason15(
            lambda: processing_module._parse_master_pointer(
                journal_size=1000, page_size=4096, path_max=512,
                tail16=b'\x00' * 17, special_and_path=b'\x00' * 14))

    def test_tail16_wrong_type_reason15(self):
        for bad in (None, 'string', [0] * 16):
            with self.subTest(tail16=type(bad).__name__):
                self._assert_reason15(lambda b=bad: processing_module._parse_master_pointer(
                    journal_size=1000, page_size=4096, path_max=512,
                    tail16=b, special_and_path=b'\x00' * 14))

    def test_checksum_wrong_primitive_reason15(self):
        for bad in ('string', None, [1], 42):
            with self.subTest(path_bytes=type(bad).__name__):
                self._assert_reason15(lambda b=bad: processing_module._sqlite_master_checksum(b))

    def test_checksum_nul_pathname_reason15(self):
        path = b'/data\x00nul'
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, 'big') + cksum.to_bytes(4, 'big') + self.MAGIC
        sj = (0x40000000 // 4096) + 1
        special_and_path = sj.to_bytes(4, 'big') + path
        self._assert_reason15(lambda: processing_module._parse_master_pointer(
            journal_size=1024, page_size=4096, path_max=512,
            tail16=tail, special_and_path=special_and_path), fragment='NUL')

    def test_special_and_path_wrong_primitive_reason15(self):
        path = b'/data/journal'
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, 'big') + cksum.to_bytes(4, 'big') + self.MAGIC
        for bad in ('string', None, [0] * (4 + len(path))):
            with self.subTest(special_and_path=type(bad).__name__):
                self._assert_reason15(lambda b=bad: processing_module._parse_master_pointer(
                    journal_size=1024, page_size=4096,
                    path_max=512, tail16=tail, special_and_path=b))

    def test_journal_size_bad_primitives_reason15(self):
        tail = self._make_tail(10)
        for bad in (True, False, 'big', -1, 2**63):
            with self.subTest(journal_size=repr(bad)):
                self._assert_reason15(lambda b=bad: processing_module._parse_master_pointer(
                    journal_size=b, page_size=4096, path_max=512,
                    tail16=tail, special_and_path=b'\x00' * 14))

    def test_path_max_bad_primitives_reason15(self):
        tail = self._make_tail(10)
        for bad in (True, 'big', 0, -1, 2**31):
            with self.subTest(path_max=repr(bad)):
                self._assert_reason15(lambda b=bad: processing_module._parse_master_pointer(
                    journal_size=1000, page_size=4096, path_max=b,
                    tail16=tail, special_and_path=b'\x00' * 14))

    def test_page_size_bad_primitives_reason15(self):
        tail = self._make_tail(10)
        for bad in (True, 'big', 0, 256, 1000, 131072):
            with self.subTest(page_size=repr(bad)):
                self._assert_reason15(lambda b=bad: processing_module._parse_master_pointer(
                    journal_size=1000, page_size=b, path_max=512,
                    tail16=tail, special_and_path=b'\x00' * 14))

    def test_journal_size_512_none(self):
        r = processing_module._parse_master_pointer(
            journal_size=512, page_size=4096, path_max=512,
            tail16=self._make_tail(10), special_and_path=b'\x00' * 14)
        self.assertEqual(r.kind, 'none')

    def test_journal_size_513_eligible(self):
        r = processing_module._parse_master_pointer(
            journal_size=513, page_size=4096, path_max=512,
            tail16=self._make_tail(0), special_and_path=b'')
        self.assertEqual(r.kind, 'none')

    def test_pointertail_bad_kind(self):
        pt_cls = type(processing_module._PointerTail('none', None))
        with self.assertRaises(ValueError): pt_cls('bogus', None)

    def test_pointertail_none_with_bytes_refused(self):
        pt_cls = type(processing_module._PointerTail('none', None))
        with self.assertRaises(ValueError): pt_cls('none', b'/some/path')

    def test_pointertail_valid_with_none_refused(self):
        pt_cls = type(processing_module._PointerTail('none', None))
        with self.assertRaises(ValueError): pt_cls('valid', None)

    def test_pointertail_valid_with_empty_refused(self):
        pt_cls = type(processing_module._PointerTail('none', None))
        with self.assertRaises(ValueError): pt_cls('valid', b'')

    def test_valid_pointer(self):
        path = b"/data/state/assessments-journal"
        tail = self._make_tail(len(path))
        special = self._make_special_and_path(path)
        # Override checksum in tail to match
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, "big") + cksum.to_bytes(4, "big") + self.MAGIC
        r = processing_module._parse_master_pointer(
            journal_size=1024,
            page_size=4096, path_max=512,
            tail16=tail, special_and_path=special,
        )
        self.assertEqual(r.kind, "valid")
        self.assertEqual(r.pathname_bytes, path)

    def test_absent_magic_none(self):
        tail = self._make_tail(10, magic=b"\x00" * 8)
        r = processing_module._parse_master_pointer(
            journal_size=100, page_size=4096, path_max=512,
            tail16=tail, special_and_path=b"\x00" * 14,
        )
        self.assertEqual(r.kind, "none")

    def test_zero_length_none(self):
        tail = self._make_tail(0)
        r = processing_module._parse_master_pointer(
            journal_size=100, page_size=4096, path_max=512,
            tail16=tail, special_and_path=b"",
        )
        self.assertEqual(r.kind, "none")

    def test_length_over_path_max_none(self):
        path_max = 64
        tail = self._make_tail(path_max + 1)
        r = processing_module._parse_master_pointer(
            journal_size=10000, page_size=4096, path_max=path_max,
            tail16=tail, special_and_path=b"x" * (path_max + 5),
        )
        self.assertEqual(r.kind, "none")

    def test_underflow_journal_size_none(self):
        path = b"/some/path"
        tail = self._make_tail(len(path))
        small_journal = 28  # too small for 20+len
        r = processing_module._parse_master_pointer(
            journal_size=small_journal, page_size=4096, path_max=512,
            tail16=tail, special_and_path=b"\x00" * 14,
        )
        self.assertEqual(r.kind, "none")

    def test_checksum_mismatch_none(self):
        path = b"/data/journal"
        wrong_checksum = 99999
        tail = (
            len(path).to_bytes(4, "big")
            + wrong_checksum.to_bytes(4, "big")
            + self.MAGIC
        )
        special = self._make_special_and_path(path)
        r = processing_module._parse_master_pointer(
            journal_size=1000, page_size=4096, path_max=512,
            tail16=tail, special_and_path=special,
        )
        self.assertEqual(r.kind, "none")

    def test_wrong_pager_reason15(self):
        path = b"/data/journal"
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, "big") + cksum.to_bytes(4, "big") + self.MAGIC
        wrong_sj = (0x40000000 // 4096) + 2  # wrong!
        special = wrong_sj.to_bytes(4, "big") + path
        with self.assertRaises(processing_module.ProcessingRefused) as ctx:
            processing_module._parse_master_pointer(
                journal_size=1000, page_size=4096, path_max=512,
                tail16=tail, special_and_path=special,
            )
        self.assertIn("PAGER_SJ_PGNO mismatch", str(ctx.exception))

    def test_short_special_and_path_reason15(self):
        path = b"/data/journal"
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, "big") + cksum.to_bytes(4, "big") + self.MAGIC
        short_special = b"\x00" * 3  # should be 4+len
        with self.assertRaises(processing_module.ProcessingRefused) as ctx:
            processing_module._parse_master_pointer(
                journal_size=1000, page_size=4096, path_max=512,
                tail16=tail, special_and_path=short_special,
            )
        self.assertIn("exactly", str(ctx.exception))

    def test_extra_special_and_path_reason15(self):
        path = b"/data/journal"
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, "big") + cksum.to_bytes(4, "big") + self.MAGIC
        extra_special = b"\x00" * (4 + len(path)) + b"extra"
        with self.assertRaises(processing_module.ProcessingRefused) as ctx:
            processing_module._parse_master_pointer(
                journal_size=1000, page_size=4096, path_max=512,
                tail16=tail, special_and_path=extra_special,
            )
        self.assertIn("exactly", str(ctx.exception))

    def test_page_size_512_valid(self):
        path = b"/j"
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, "big") + cksum.to_bytes(4, "big") + self.MAGIC
        sj = (0x40000000 // 512) + 1
        special = sj.to_bytes(4, "big") + path
        r = processing_module._parse_master_pointer(
            journal_size=1000, page_size=512, path_max=512,
            tail16=tail, special_and_path=special,
        )
        self.assertEqual(r.kind, "valid")

    def test_page_size_65536_valid(self):
        path = b"/j"
        cksum = processing_module._sqlite_master_checksum(path)
        tail = len(path).to_bytes(4, "big") + cksum.to_bytes(4, "big") + self.MAGIC
        sj = (0x40000000 // 65536) + 1
        special = sj.to_bytes(4, "big") + path
        r = processing_module._parse_master_pointer(
                journal_size=1000, page_size=65536, path_max=512,
                tail16=tail, special_and_path=special,
            )
        self.assertEqual(r.kind, "valid")


class StageDPart3C2SidecarCaptureTests(TempRootTestCase):
    def test_cold_capture_is_fd_free_and_leaves_descriptor_owner_unchanged(self):
        pm = processing_module
        baseline = len(os.listdir("/dev/fd"))
        harness = StageDPart3AReplayTests(
            "test_exact_replay_of_sealed_receipt"
        )
        harness.setUp()
        descriptors = None
        owner = None
        owner_closed = False
        try:
            world = harness._new_world()
            main_db, vac_db = harness._databases(
                world, canonical_store=False
            )
            payload = harness._payload(world, main_db, vac_db)
            name = harness._stage(world, payload)
            descriptors, loaded, file_sha, _semantic = (
                pm.load_envelope_authority(world["data"], name)
            )
            facts = pm.compose_envelope_facts(
                loaded,
                envelope_file_sha256=file_sha,
                expected_assessments_path=str(main_db),
                expected_vacancy_path=str(vac_db),
            )
            admission = pm.admit_config_and_databases(
                world["data"], facts, descriptors
            )

            def descriptor_snapshot():
                return (
                    id(descriptors),
                    id(descriptors.root),
                    id(descriptors.directories),
                    tuple(id(level) for level in descriptors.directories),
                    tuple(
                        (level.fd, pm._identity(os.fstat(level.fd)))
                        for level in descriptors.directories
                    ),
                    id(descriptors.db_leaves),
                    tuple(id(leaf) for leaf in descriptors.db_leaves),
                    tuple(
                        (leaf.fd, leaf.identity, pm._identity(os.fstat(leaf.fd)))
                        for leaf in descriptors.db_leaves
                    ),
                )

            retained_before = descriptor_snapshot()
            admitted_fd_count = len(os.listdir("/dev/fd"))
            owner = pm._SidecarPairCapture(
                descriptors,
                admission["assessments"],
                admission["vacancy"],
            )
            self.assertIsInstance(owner.records, tuple)
            self.assertEqual(len(owner.records), 6)
            self.assertTrue(all(not record.present for record in owner.records))
            self.assertEqual(len(os.listdir("/dev/fd")), admitted_fd_count)
            self.assertEqual(descriptor_snapshot(), retained_before)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                owner.records[0].present = True
            with self.assertRaises(AttributeError):
                owner.records += ()
            owner.close()
            owner_closed = True
            self.assertEqual(descriptor_snapshot(), retained_before)
        finally:
            try:
                if owner is not None and not owner_closed:
                    owner.close()
            finally:
                try:
                    if descriptors is not None:
                        for leaf in list(descriptors.db_leaves):
                            leaf.close(descriptors)
                        descriptors.close()
                finally:
                    harness.doCleanups()
        self.assertEqual(len(os.listdir("/dev/fd")), baseline)

    def test_one_present_journal_is_retained_until_owner_close(self):
        pm = processing_module
        baseline = len(os.listdir("/dev/fd"))
        harness = StageDPart3AReplayTests(
            "test_exact_replay_of_sealed_receipt"
        )
        harness.setUp()
        descriptors = None
        owner = None
        owner_closed = False
        try:
            world = harness._new_world()
            main_db, vac_db = harness._databases(
                world, canonical_store=False
            )
            payload = harness._payload(world, main_db, vac_db)
            name = harness._stage(world, payload)
            journal = main_db.parent / (main_db.name + "-journal")
            journal.write_bytes(b"sidecar-phase-one")
            os.chmod(journal, 0o600)
            journal_info = os.stat(journal)
            descriptors, loaded, file_sha, _semantic = (
                pm.load_envelope_authority(world["data"], name)
            )
            facts = pm.compose_envelope_facts(
                loaded,
                envelope_file_sha256=file_sha,
                expected_assessments_path=str(main_db),
                expected_vacancy_path=str(vac_db),
            )
            admission = pm.admit_config_and_databases(
                world["data"], facts, descriptors
            )

            def descriptor_snapshot():
                return (
                    id(descriptors),
                    id(descriptors.root),
                    id(descriptors.directories),
                    tuple(id(level) for level in descriptors.directories),
                    tuple(
                        (level.fd, pm._identity(os.fstat(level.fd)))
                        for level in descriptors.directories
                    ),
                    id(descriptors.db_leaves),
                    tuple(id(leaf) for leaf in descriptors.db_leaves),
                    tuple(
                        (leaf.fd, leaf.identity, pm._identity(os.fstat(leaf.fd)))
                        for leaf in descriptors.db_leaves
                    ),
                )

            retained_before = descriptor_snapshot()
            admitted_fd_count = len(os.listdir("/dev/fd"))
            owner = pm._SidecarPairCapture(
                descriptors,
                admission["assessments"],
                admission["vacancy"],
            )
            present = tuple(record for record in owner.records if record.present)
            self.assertEqual(len(present), 1)
            self.assertEqual(len(owner.records), 6)
            record = present[0]
            self.assertEqual(record.database, "assessments")
            self.assertEqual(record.name, main_db.name + "-journal")
            self.assertEqual(record.suffix, "-journal")
            self.assertEqual(record.identity, pm._identity(journal_info))
            self.assertEqual(record.size, len(b"sidecar-phase-one"))
            self.assertEqual(len(os.listdir("/dev/fd")), admitted_fd_count + 1)
            self.assertEqual(descriptor_snapshot(), retained_before)
            owner.close()
            owner_closed = True
            self.assertEqual(len(os.listdir("/dev/fd")), admitted_fd_count)
            self.assertEqual(descriptor_snapshot(), retained_before)
        finally:
            try:
                if owner is not None and not owner_closed:
                    owner.close()
            finally:
                try:
                    if descriptors is not None:
                        for leaf in list(descriptors.db_leaves):
                            leaf.close(descriptors)
                        descriptors.close()
                finally:
                    harness.doCleanups()
        self.assertEqual(len(os.listdir("/dev/fd")), baseline)


class StageDPart3C2SidecarHardeningTests(TempRootTestCase):
    def _manual_pair(self, *, journal: bytes | None = None):
        pm = processing_module
        pair_root = pathlib.Path(tempfile.mkdtemp(dir=self.root))
        assessments_parent = pair_root / "assessments-parent"
        vacancy_parent = pair_root / "vacancy-parent"
        assessments_parent.mkdir()
        vacancy_parent.mkdir()
        os.chmod(assessments_parent, 0o700)
        os.chmod(vacancy_parent, 0o700)
        assessments_path = assessments_parent / "assessments.sqlite3"
        vacancy_path = vacancy_parent / "vacancies.sqlite3"
        assessments_path.write_bytes(b"assessment-db")
        vacancy_path.write_bytes(b"vacancy-db")
        os.chmod(assessments_path, 0o600)
        os.chmod(vacancy_path, 0o600)
        if journal is not None:
            journal_path = assessments_parent / "assessments.sqlite3-journal"
            journal_path.write_bytes(journal)
            os.chmod(journal_path, 0o600)
        descriptors = pm._DescriptorSet()
        self.addCleanup(descriptors.close)
        assessments_level = descriptors.push_directory(
            pm._RetainedDirectory(
                None, None, at=str(assessments_parent)
            )
        )
        vacancy_level = descriptors.push_directory(
            pm._RetainedDirectory(None, None, at=str(vacancy_parent))
        )
        assessments = pm._RetainedDatabaseLeaf(
            assessments_level,
            assessments_path.name,
            pm._identity(os.stat(assessments_path)),
            "assessments",
            descriptors,
            absolute_path=str(assessments_path),
        )
        vacancy = pm._RetainedDatabaseLeaf(
            vacancy_level,
            vacancy_path.name,
            pm._identity(os.stat(vacancy_path)),
            "vacancy",
            descriptors,
            absolute_path=str(vacancy_path),
        )
        return (
            descriptors,
            assessments,
            vacancy,
            assessments_path,
            vacancy_path,
        )

    def test_distinct_parent_path_maxima_are_acquired_and_strict(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, _main, _vac = self._manual_pair()
        observed = []

        def different_path_max(fd, key):
            observed.append((fd, key))
            if fd == assessments.parent.fd:
                return 1024
            if fd == vacancy.parent.fd:
                return 4096
            raise AssertionError("unexpected parent fd")

        with mock.patch.object(
            pm.os, "fpathconf", side_effect=different_path_max
        ):
            owner = pm._SidecarPairCapture(
                descriptors, assessments, vacancy
            )
        try:
            self.assertEqual(owner.path_maxima, (1024, 4096))
            self.assertEqual(
                observed,
                [
                    (assessments.parent.fd, "PC_PATH_MAX"),
                    (vacancy.parent.fd, "PC_PATH_MAX"),
                ],
            )
        finally:
            owner.close()

        for value in (True, "1024", 0, -1, pm._MAX_PRIVATE_PATH_MAX + 1):
            with self.subTest(value=value), mock.patch.object(
                pm.os, "fpathconf", return_value=value
            ):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._sidecar_path_max(assessments.parent.fd, "assessments")
                self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)

    def test_constructor_prevalidates_unsafe_sidecars_without_opening(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in (
            "fifo",
            "symlink",
            "hardlink",
            "mode_0644",
            "mode_0664",
        ):
            with self.subTest(variant=variant):
                (
                    descriptors,
                    assessments,
                    vacancy,
                    main_path,
                    _vacancy_path,
                ) = self._manual_pair()
                journal = main_path.parent / (main_path.name + "-journal")
                target = main_path.parent / "target"
                target.write_bytes(b"target")
                os.chmod(target, 0o600)
                if variant == "fifo":
                    os.mkfifo(journal, 0o600)
                elif variant == "symlink":
                    journal.symlink_to(target)
                elif variant == "hardlink":
                    os.link(target, journal)
                else:
                    journal.write_bytes(b"unsafe mode")
                    os.chmod(
                        journal, 0o644 if variant == "mode_0644" else 0o664
                    )

                real_open = pm.os.open
                sidecar_opens = []

                def forbid_sidecar_open(path, flags, *args, **kwargs):
                    if (
                        path == journal.name
                        and kwargs.get("dir_fd") == assessments.parent.fd
                    ):
                        sidecar_opens.append((path, flags))
                        raise AssertionError("unsafe sidecar reached os.open")
                    return real_open(path, flags, *args, **kwargs)

                try:
                    with mock.patch.object(
                        pm.os, "open", side_effect=forbid_sidecar_open
                    ):
                        with self.assertRaises(pm.ProcessingRefused) as caught:
                            pm._SidecarPairCapture(
                                descriptors, assessments, vacancy
                            )
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                    self.assertEqual(sidecar_opens, [])
                finally:
                    descriptors.close()

    def test_constructor_wrong_owner_prestat_refuses_without_opening(self):
        import unittest.mock as mock

        pm = processing_module
        (
            descriptors,
            assessments,
            vacancy,
            main_path,
            _vacancy_path,
        ) = self._manual_pair(journal=b"private journal")
        journal = main_path.parent / (main_path.name + "-journal")
        real_stat = pm.os.stat
        real_open = pm.os.open
        injected = list(real_stat(journal))
        injected[4] = os.getuid() + 1
        wrong_owner = os.stat_result(injected)
        sidecar_opens = []

        def injected_stat(path, *args, **kwargs):
            if (
                path == journal.name
                and kwargs.get("dir_fd") == assessments.parent.fd
            ):
                return wrong_owner
            return real_stat(path, *args, **kwargs)

        def forbid_sidecar_open(path, flags, *args, **kwargs):
            if (
                path == journal.name
                and kwargs.get("dir_fd") == assessments.parent.fd
            ):
                sidecar_opens.append((path, flags))
                raise AssertionError("wrong-owner sidecar reached os.open")
            return real_open(path, flags, *args, **kwargs)

        try:
            with mock.patch.object(
                pm.os, "stat", side_effect=injected_stat
            ), mock.patch.object(
                pm.os, "open", side_effect=forbid_sidecar_open
            ):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._SidecarPairCapture(descriptors, assessments, vacancy)
            self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
            self.assertIn("current UID", str(caught.exception))
            self.assertEqual(sidecar_opens, [])
        finally:
            descriptors.close()

    def test_constructor_stat_open_fifo_swap_is_nonblocking_and_fd_stable(self):
        import unittest.mock as mock

        pm = processing_module
        (
            descriptors,
            assessments,
            vacancy,
            main_path,
            _vacancy_path,
        ) = self._manual_pair(journal=b"private journal")
        journal = main_path.parent / (main_path.name + "-journal")
        real_open = pm.os.open
        baseline = len(os.listdir("/dev/fd"))
        observed_flags = []

        def swap_to_fifo(path, flags, *args, **kwargs):
            if (
                path == journal.name
                and kwargs.get("dir_fd") == assessments.parent.fd
            ):
                observed_flags.append(flags)
                journal.unlink()
                os.mkfifo(journal, 0o600)
            return real_open(path, flags, *args, **kwargs)

        started = time.monotonic()
        try:
            with mock.patch.object(pm.os, "open", side_effect=swap_to_fifo):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._SidecarPairCapture(descriptors, assessments, vacancy)
            elapsed = time.monotonic() - started
            self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
            self.assertLess(elapsed, 1.0)
            self.assertEqual(len(observed_flags), 1)
            self.assertTrue(observed_flags[0] & os.O_NONBLOCK)
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        finally:
            descriptors.close()

    def test_constructor_fails_closed_when_nonblock_is_unavailable(self):
        import unittest.mock as mock

        pm = processing_module
        (
            descriptors,
            assessments,
            vacancy,
            main_path,
            _vacancy_path,
        ) = self._manual_pair(journal=b"private journal")
        journal_name = main_path.name + "-journal"
        real_open = pm.os.open
        sidecar_opens = []

        def forbid_sidecar_open(path, flags, *args, **kwargs):
            if (
                path == journal_name
                and kwargs.get("dir_fd") == assessments.parent.fd
            ):
                sidecar_opens.append((path, flags))
                raise AssertionError("sidecar opened without O_NONBLOCK")
            return real_open(path, flags, *args, **kwargs)

        try:
            with mock.patch.object(
                pm.os, "O_NONBLOCK", None
            ), mock.patch.object(
                pm.os, "open", side_effect=forbid_sidecar_open
            ):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._SidecarPairCapture(descriptors, assessments, vacancy)
            self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
            self.assertIn("O_NONBLOCK", str(caught.exception))
            self.assertEqual(sidecar_opens, [])
        finally:
            descriptors.close()

    def test_safe_private_state_changes_raise_only_churn(self):
        pm = processing_module
        for variant in ("appearance", "disappearance", "inode", "size"):
            with self.subTest(variant=variant):
                initial = None if variant == "appearance" else b"x" * 100
                (
                    descriptors,
                    assessments,
                    vacancy,
                    main_path,
                    _vacancy_path,
                ) = self._manual_pair(journal=initial)
                journal = main_path.parent / (main_path.name + "-journal")
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                try:
                    if variant == "appearance":
                        journal.write_bytes(b"appeared")
                        os.chmod(journal, 0o600)
                    elif variant == "disappearance":
                        journal.unlink()
                    elif variant == "inode":
                        replacement = main_path.parent / "replacement"
                        replacement.write_bytes(b"x" * 100)
                        os.chmod(replacement, 0o600)
                        os.replace(replacement, journal)
                    else:
                        with journal.open("ab") as stream:
                            stream.write(b"growth")
                    with self.assertRaises(pm._SidecarChurn):
                        owner.revalidate()
                finally:
                    owner.close()
                    descriptors.close()

    def test_unsafe_objects_raise_reason15_not_churn(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in (
            "symlink",
            "hardlink",
            "mode_0644",
            "mode_0664",
            "nonregular",
        ):
            with self.subTest(variant=variant):
                (
                    descriptors,
                    assessments,
                    vacancy,
                    main_path,
                    _vacancy_path,
                ) = self._manual_pair()
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                journal = main_path.parent / (main_path.name + "-journal")
                target = main_path.parent / "target"
                target.write_bytes(b"target")
                os.chmod(target, 0o600)
                if variant == "symlink":
                    journal.symlink_to(target)
                elif variant == "hardlink":
                    os.link(target, journal)
                elif variant == "nonregular":
                    os.mkfifo(journal, 0o600)
                else:
                    journal.write_bytes(b"unsafe mode")
                    os.chmod(
                        journal, 0o644 if variant == "mode_0644" else 0o664
                    )
                try:
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        owner.revalidate()
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                finally:
                    owner.close()
                    descriptors.close()

        (
            descriptors,
            assessments,
            vacancy,
            main_path,
            _vacancy_path,
        ) = self._manual_pair()
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        real_stat = pm.os.stat
        journal_name = main_path.name + "-journal"

        def unstatable_sidecar(path, *args, **kwargs):
            if (
                path == journal_name
                and kwargs.get("dir_fd") == assessments.parent.fd
            ):
                raise PermissionError(errno.EACCES, "injected unstatable")
            return real_stat(path, *args, **kwargs)

        try:
            with mock.patch.object(
                pm.os, "stat", side_effect=unstatable_sidecar
            ):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    owner.revalidate()
            self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
        finally:
            owner.close()
            descriptors.close()

    def test_database_and_parent_drift_remain_reason5(self):
        pm = processing_module
        for variant in ("database", "parent"):
            with self.subTest(variant=variant):
                (
                    descriptors,
                    assessments,
                    vacancy,
                    main_path,
                    _vacancy_path,
                ) = self._manual_pair()
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                try:
                    if variant == "database":
                        replacement = main_path.parent / "replacement-db"
                        replacement.write_bytes(b"assessment-db")
                        os.chmod(replacement, 0o600)
                        os.replace(replacement, main_path)
                    else:
                        os.chmod(main_path.parent, 0o755)
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        owner.revalidate()
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_CONFIG_DATABASE
                    )
                finally:
                    owner.close()
                    descriptors.close()

    def test_revalidate_proves_chain_first_and_last_even_on_churn(self):
        import unittest.mock as mock

        pm = processing_module
        (
            descriptors,
            assessments,
            vacancy,
            main_path,
            _vacancy_path,
        ) = self._manual_pair()
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        journal = main_path.parent / (main_path.name + "-journal")
        journal.write_bytes(b"appeared")
        os.chmod(journal, 0o600)
        calls = []
        real_assert = pm._assert_chain_intact

        def counted_assert(*args, **kwargs):
            calls.append((args, kwargs))
            return real_assert(*args, **kwargs)

        try:
            with mock.patch.object(
                pm, "_assert_chain_intact", side_effect=counted_assert
            ):
                with self.assertRaises(pm._SidecarChurn):
                    owner.revalidate()
            self.assertEqual(len(calls), 2)
            self.assertTrue(
                all(
                    call_kwargs["allow_sidecar_parent_nlink_churn"]
                    for _call_args, call_kwargs in calls
                )
            )
        finally:
            owner.close()
            descriptors.close()

    def test_bounded_pread_accepts_only_exact_shapes_and_detects_short_extra(self):
        import unittest.mock as mock

        pm = processing_module
        content = bytes(range(100))
        (
            descriptors,
            assessments,
            vacancy,
            _main,
            _vacancy_path,
        ) = self._manual_pair(journal=content)
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        try:
            self.assertEqual(
                owner._pread_exact(
                    "assessments",
                    "-journal",
                    purpose="header",
                    offset=0,
                    length=28,
                ),
                content[:28],
            )
            self.assertEqual(
                owner._pread_exact(
                    "assessments",
                    "-journal",
                    purpose="tail",
                    offset=84,
                    length=16,
                ),
                content[84:],
            )
            self.assertEqual(
                owner._pread_exact(
                    "assessments",
                    "-journal",
                    purpose="pointer",
                    offset=76,
                    length=8,
                ),
                content[76:84],
            )
            for purpose, offset, length in (
                ("header", 1, 28),
                ("tail", 0, 16),
                ("pointer", 0, 100),
                ("whole", 0, 100),
            ):
                with self.subTest(shape=(purpose, offset, length)):
                    with self.assertRaises(pm.ProcessingRefused):
                        owner._pread_exact(
                            "assessments",
                            "-journal",
                            purpose=purpose,
                            offset=offset,
                            length=length,
                        )
            with mock.patch.object(pm.os, "pread", return_value=b""):
                with self.assertRaises(pm._SidecarChurn):
                    owner._pread_exact(
                        "assessments",
                        "-journal",
                        purpose="header",
                        offset=0,
                        length=28,
                    )
            with mock.patch.object(pm.os, "pread", return_value=b"x" * 29):
                with self.assertRaises(pm._SidecarChurn):
                    owner._pread_exact(
                        "assessments",
                        "-journal",
                        purpose="header",
                        offset=0,
                        length=28,
                    )
        finally:
            owner.close()
            descriptors.close()

    def test_pread_identity_and_size_drift_are_churn(self):
        pm = processing_module
        for variant in ("identity", "size"):
            with self.subTest(variant=variant):
                (
                    descriptors,
                    assessments,
                    vacancy,
                    main_path,
                    _vacancy_path,
                ) = self._manual_pair(journal=b"x" * 100)
                journal = main_path.parent / (main_path.name + "-journal")
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                try:
                    if variant == "identity":
                        replacement = main_path.parent / "replacement"
                        replacement.write_bytes(b"x" * 100)
                        os.chmod(replacement, 0o600)
                        os.replace(replacement, journal)
                    else:
                        with journal.open("ab") as stream:
                            stream.write(b"growth")
                    with self.assertRaises(pm._SidecarChurn):
                        owner._pread_exact(
                            "assessments",
                            "-journal",
                            purpose="header",
                            offset=0,
                            length=28,
                        )
                finally:
                    owner.close()
                    descriptors.close()

    def test_close_ambiguity_is_sticky_and_never_retries_fd_number(self):
        import unittest.mock as mock

        pm = processing_module
        (
            descriptors,
            assessments,
            vacancy,
            _main,
            _vacancy_path,
        ) = self._manual_pair(journal=b"x" * 100)
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        real_close = os.close
        calls = []

        def ambiguous_close(fd):
            calls.append(fd)
            raise OSError(errno.EIO, "injected close ambiguity")

        with mock.patch.object(pm.os, "close", side_effect=ambiguous_close):
            with self.assertRaises(pm.ProcessingRefused) as first:
                owner.close()
            self.assertEqual(first.exception.reason, pm.REASON_ATOMIC_MODE)
            with self.assertRaises(pm.ProcessingRefused) as second:
                owner.close()
            self.assertIs(second.exception, first.exception)
        self.assertEqual(len(calls), 1)
        real_close(calls[0])
        descriptors.close()

    def test_repeated_success_and_refusal_keep_exact_fd_baseline(self):
        pm = processing_module
        (
            descriptors,
            assessments,
            vacancy,
            main_path,
            _vacancy_path,
        ) = self._manual_pair(journal=b"x" * 100)
        baseline = len(os.listdir("/dev/fd"))
        for _ in range(50):
            owner = pm._SidecarPairCapture(
                descriptors, assessments, vacancy
            )
            owner.revalidate()
            owner.close()
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)

        journal = main_path.parent / (main_path.name + "-journal")
        os.chmod(journal, 0o644)
        for _ in range(50):
            with self.assertRaises(pm.ProcessingRefused) as caught:
                pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
            self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        descriptors.close()


class StageDPart3C2JournalObservationTests(TempRootTestCase):
    MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

    def _manual_pair(self, *, journal: bytes | None = None):
        return StageDPart3C2SidecarHardeningTests._manual_pair(
            self, journal=journal
        )

    def _header(self, *, sector: int = 4096, page: int = 4096) -> bytes:
        return b"".join(
            (
                self.MAGIC,
                (3).to_bytes(4, "big"),
                (0xABCDEF01).to_bytes(4, "big"),
                (16).to_bytes(4, "big"),
                sector.to_bytes(4, "big"),
                page.to_bytes(4, "big"),
            )
        )

    def _journal_bytes(
        self,
        *,
        size: int = 1024,
        pointer_path: bytes | None = None,
        header: bytes | None = None,
    ) -> bytes:
        if size < 28:
            raise AssertionError("candidate fixture must hold its header")
        data = bytearray(size)
        data[:28] = self._header() if header is None else header
        if pointer_path is not None:
            checksum = processing_module._sqlite_master_checksum(pointer_path)
            special_page = (0x40000000 // 4096) + 1
            special_and_path = special_page.to_bytes(4, "big") + pointer_path
            tail = (
                len(pointer_path).to_bytes(4, "big")
                + checksum.to_bytes(4, "big")
                + self.MAGIC
            )
            start = size - len(special_and_path) - len(tail)
            if start < 28:
                raise AssertionError("candidate fixture pointer overlaps header")
            data[start : start + len(special_and_path)] = special_and_path
            data[-16:] = tail
        return bytes(data)

    def _write_vacancy_journal(
        self, vacancy_path: pathlib.Path, content: bytes
    ) -> pathlib.Path:
        journal = vacancy_path.parent / (vacancy_path.name + "-journal")
        journal.write_bytes(content)
        os.chmod(journal, 0o600)
        return journal

    def test_absent_journals_return_frozen_fd_free_facts(self):
        pm = processing_module
        descriptors, assessments, vacancy, _main, _vac = self._manual_pair()
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        try:
            facts = owner.observe_journals()
            self.assertEqual(len(facts), 2)
            self.assertEqual(
                tuple(fact.database for fact in facts),
                ("assessments", "vacancy"),
            )
            for fact in facts:
                self.assertEqual(fact.state, "absent")
                self.assertIsNone(fact.size)
                self.assertEqual(fact.prefix, b"")
                self.assertIsNone(fact.header)
                self.assertIsNone(fact.tail16)
                self.assertIsNone(fact.pointer)
                self.assertIsNone(fact.pointer_path)
                self.assertNotIn("fd", {field.name for field in dataclasses.fields(fact)})
            with self.assertRaises(dataclasses.FrozenInstanceError):
                facts[0].state = "candidate"
        finally:
            owner.close()
            descriptors.close()

    def test_small_and_malformed_journals_are_explicit_noncandidates(self):
        pm = processing_module
        for size in (0, 1, 27, 28, 512):
            with self.subTest(size=size):
                content = (self._header() + b"x" * 512)[:size]
                descriptors, assessments, vacancy, _main, _vac = (
                    self._manual_pair(journal=content)
                )
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                try:
                    fact = owner.observe_journals()[0]
                    self.assertEqual(fact.state, "noncandidate")
                    self.assertEqual(fact.size, size)
                    self.assertEqual(fact.prefix, content[:28])
                    self.assertFalse(fact.header.candidate)
                    self.assertIsNone(fact.tail16)
                    self.assertIsNone(fact.pointer)
                finally:
                    owner.close()
                    descriptors.close()

        for label, content in (
            ("wrong magic", b"x" * 513),
            (
                "invalid sector",
                self._journal_bytes(
                    size=513, header=self._header(sector=1000)
                ),
            ),
            (
                "invalid page",
                self._journal_bytes(
                    size=513, header=self._header(page=1000)
                ),
            ),
        ):
            with self.subTest(label=label):
                descriptors, assessments, vacancy, _main, _vac = (
                    self._manual_pair(journal=content)
                )
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                try:
                    fact = owner.observe_journals()[0]
                    self.assertEqual(fact.state, "noncandidate")
                    self.assertFalse(fact.header.candidate)
                finally:
                    owner.close()
                    descriptors.close()

    def test_513_byte_candidate_without_pointer_is_observed(self):
        pm = processing_module
        descriptors, assessments, vacancy, _main, _vac = self._manual_pair(
            journal=self._journal_bytes(size=513)
        )
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        try:
            fact = owner.observe_journals()[0]
            self.assertEqual(fact.state, "candidate")
            self.assertEqual(fact.size, 513)
            self.assertTrue(fact.header.candidate)
            self.assertEqual(fact.tail16, b"\x00" * 16)
            self.assertEqual(fact.pointer.kind, "none")
            self.assertIsNone(fact.pointer_path)
        finally:
            owner.close()
            descriptors.close()

    def test_both_distinct_parent_journals_point_to_one_main_parent_master(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, main_path, vacancy_path = (
            self._manual_pair()
        )
        main_master = main_path.parent / "main master #1"
        main_journal = main_path.parent / (main_path.name + "-journal")
        main_journal.write_bytes(
            self._journal_bytes(pointer_path=os.fsencode(main_master))
        )
        os.chmod(main_journal, 0o600)
        self._write_vacancy_journal(
            vacancy_path,
            self._journal_bytes(pointer_path=os.fsencode(main_master)),
        )
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        opens = []

        def forbid_new_open(path, flags, *args, **kwargs):
            opens.append((path, flags, kwargs.get("dir_fd")))
            raise AssertionError("journal observation opened another path")

        try:
            with mock.patch.object(
                pm.os, "open", side_effect=forbid_new_open
            ):
                facts = owner.observe_journals()
            self.assertEqual(opens, [])
            self.assertEqual(
                tuple(fact.pointer_path for fact in facts),
                (str(main_master), str(main_master)),
            )
            self.assertTrue(all(fact.pointer.kind == "valid" for fact in facts))
            self.assertFalse(main_master.exists())
        finally:
            owner.close()
            descriptors.close()

    def test_pointer_path_authority_rejects_every_noncanonical_form(self):
        pm = processing_module
        variants = (
            ("non_utf8", lambda main, vacancy: os.fsencode(main.parent) + b"/\xff"),
            ("nul", lambda main, vacancy: os.fsencode(main.parent) + b"/bad\x00name"),
            ("relative", lambda main, vacancy: b"relative-master"),
            ("dot", lambda main, vacancy: os.fsencode(main.parent) + b"/./master"),
            (
                "dotdot",
                lambda main, vacancy: os.fsencode(main.parent) + b"/../master",
            ),
            (
                "nested",
                lambda main, vacancy: os.fsencode(main.parent) + b"/nested/master",
            ),
            (
                "alias",
                lambda main, vacancy: os.fsencode(main.parent) + b"//master",
            ),
            ("escape", lambda main, vacancy: b"/tmp/outside/master"),
            (
                "wrong_parent",
                lambda main, vacancy: os.fsencode(vacancy.parent / "master"),
            ),
        )
        for source_database in ("assessments", "vacancy"):
            for label, make_path in variants:
                with self.subTest(source=source_database, label=label):
                    (
                        descriptors,
                        assessments,
                        vacancy,
                        main_path,
                        vacancy_path,
                    ) = self._manual_pair()
                    pointer_path = make_path(main_path, vacancy_path)
                    content = self._journal_bytes(pointer_path=pointer_path)
                    if source_database == "assessments":
                        journal = main_path.parent / (
                            main_path.name + "-journal"
                        )
                        journal.write_bytes(content)
                        os.chmod(journal, 0o600)
                    else:
                        self._write_vacancy_journal(vacancy_path, content)
                    owner = pm._SidecarPairCapture(
                        descriptors, assessments, vacancy
                    )
                    try:
                        with self.assertRaises(pm.ProcessingRefused) as caught:
                            owner.observe_journals()
                        self.assertEqual(
                            caught.exception.reason, pm.REASON_ATOMIC_MODE
                        )
                    finally:
                        owner.close()
                        descriptors.close()

    def test_wal_or_shm_presence_refuses_reason15(self):
        pm = processing_module
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                descriptors, assessments, vacancy, main_path, _vacancy_path = (
                    self._manual_pair()
                )
                sidecar = main_path.parent / (main_path.name + suffix)
                sidecar.write_bytes(b"private sqlite sidecar")
                os.chmod(sidecar, 0o600)
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                try:
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        owner.observe_journals()
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                finally:
                    owner.close()
                    descriptors.close()

    def test_candidate_reads_only_header_tail_eof_and_exact_pointer(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, main_path, _vacancy_path = (
            self._manual_pair()
        )
        master = main_path.parent / "master"
        pointer_path = os.fsencode(master)
        content = self._journal_bytes(pointer_path=pointer_path)
        journal = main_path.parent / (main_path.name + "-journal")
        journal.write_bytes(content)
        os.chmod(journal, 0o600)
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        real_pread = pm.os.pread
        calls = []

        def observed_pread(fd, length, offset):
            calls.append((length, offset))
            return real_pread(fd, length, offset)

        try:
            with mock.patch.object(
                pm.os, "pread", side_effect=observed_pread
            ):
                fact = owner.observe_journals()[0]
            pointer_length = 4 + len(pointer_path)
            self.assertEqual(
                calls,
                [
                    (28, 0),
                    (16, len(content) - 16),
                    (1, len(content)),
                    (
                        pointer_length,
                        len(content) - 16 - pointer_length,
                    ),
                ],
            )
            self.assertNotIn(len(content), tuple(length for length, _ in calls))
            self.assertEqual(fact.pointer_path, str(master))
        finally:
            owner.close()
            descriptors.close()

    def test_mid_prefix_read_churn_and_short_read_keep_fd_baseline(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in ("growth", "short"):
            with self.subTest(variant=variant):
                descriptors, assessments, vacancy, main_path, _vacancy_path = (
                    self._manual_pair(journal=self._journal_bytes())
                )
                journal = main_path.parent / (main_path.name + "-journal")
                owner = pm._SidecarPairCapture(
                    descriptors, assessments, vacancy
                )
                baseline = len(os.listdir("/dev/fd"))
                real_pread = pm.os.pread
                injected = False

                def faulted_pread(fd, length, offset):
                    nonlocal injected
                    if not injected and length == 28 and offset == 0:
                        injected = True
                        if variant == "short":
                            return b""
                        result = real_pread(fd, length, offset)
                        with journal.open("ab") as stream:
                            stream.write(b"growth")
                        return result
                    return real_pread(fd, length, offset)

                try:
                    with mock.patch.object(
                        pm.os, "pread", side_effect=faulted_pread
                    ):
                        with self.assertRaises(pm._SidecarChurn):
                            owner.observe_journals()
                    self.assertTrue(injected)
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline)
                finally:
                    owner.close()
                    self.assertEqual(
                        len(os.listdir("/dev/fd")), baseline - 1
                    )
                    descriptors.close()

    def test_repeated_observation_is_fd_stable(self):
        pm = processing_module
        descriptors, assessments, vacancy, _main, _vacancy_path = (
            self._manual_pair(journal=self._journal_bytes(size=513))
        )
        owner = pm._SidecarPairCapture(descriptors, assessments, vacancy)
        baseline = len(os.listdir("/dev/fd"))
        try:
            for _ in range(50):
                facts = owner.observe_journals()
                self.assertEqual(facts[0].state, "candidate")
                self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        finally:
            owner.close()
            self.assertEqual(len(os.listdir("/dev/fd")), baseline - 1)
            descriptors.close()


class StageDPart3C2MasterJournalCaptureTests(TempRootTestCase):
    MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

    def _manual_pair(self):
        return StageDPart3C2SidecarHardeningTests._manual_pair(self)

    def _header(self) -> bytes:
        return b"".join(
            (
                self.MAGIC,
                (3).to_bytes(4, "big"),
                (0xABCDEF01).to_bytes(4, "big"),
                (16).to_bytes(4, "big"),
                (4096).to_bytes(4, "big"),
                (4096).to_bytes(4, "big"),
            )
        )

    def _journal_bytes(
        self, pointer_path: bytes | None, *, size: int = 1024
    ) -> bytes:
        data = bytearray(size)
        data[:28] = self._header()
        if pointer_path is not None:
            checksum = processing_module._sqlite_master_checksum(pointer_path)
            special_page = (0x40000000 // 4096) + 1
            special_and_path = special_page.to_bytes(4, "big") + pointer_path
            tail = (
                len(pointer_path).to_bytes(4, "big")
                + checksum.to_bytes(4, "big")
                + self.MAGIC
            )
            start = size - len(special_and_path) - len(tail)
            if start < 28:
                raise AssertionError("pointer fixture overlaps header")
            data[start : start + len(special_and_path)] = special_and_path
            data[-16:] = tail
        return bytes(data)

    def _prepare(
        self,
        *,
        master_content: bytes | None = None,
        create_master: bool = True,
        main_pointer: pathlib.Path | None = None,
        vacancy_pointer: pathlib.Path | None = None,
    ):
        pm = processing_module
        descriptors, assessments, vacancy, main_path, vacancy_path = (
            self._manual_pair()
        )
        master = main_path.parent / "shared-master"
        if main_pointer is None:
            main_pointer = master
        if vacancy_pointer is None:
            vacancy_pointer = master
        main_journal = main_path.parent / (main_path.name + "-journal")
        vacancy_journal = vacancy_path.parent / (
            vacancy_path.name + "-journal"
        )
        main_journal.write_bytes(
            self._journal_bytes(os.fsencode(main_pointer))
        )
        vacancy_journal.write_bytes(
            self._journal_bytes(os.fsencode(vacancy_pointer))
        )
        os.chmod(main_journal, 0o600)
        os.chmod(vacancy_journal, 0o600)
        if master_content is None:
            master_content = (
                os.fsencode(main_journal)
                + b"\x00"
                + os.fsencode(vacancy_journal)
                + b"\x00"
            )
        if create_master:
            master.write_bytes(master_content)
            os.chmod(master, 0o600)
        sidecars = pm._SidecarPairCapture(
            descriptors, assessments, vacancy
        )
        journals = sidecars.observe_journals()
        return (
            descriptors,
            assessments,
            vacancy,
            sidecars,
            journals,
            main_path,
            vacancy_path,
            main_journal,
            vacancy_journal,
            master,
            master_content,
        )

    def test_no_pointers_returns_frozen_none_fact_without_new_fd(self):
        pm = processing_module
        descriptors, assessments, vacancy, _main, _vacancy = (
            self._manual_pair()
        )
        sidecars = pm._SidecarPairCapture(
            descriptors, assessments, vacancy
        )
        journals = sidecars.observe_journals()
        baseline = len(os.listdir("/dev/fd"))
        capture = pm._MasterJournalCapture(sidecars, journals)
        try:
            self.assertEqual(capture.fact.state, "none")
            self.assertIsNone(capture.fact.path)
            self.assertIsNone(capture.fact.size)
            self.assertEqual(capture.fact.entries, ())
            self.assertEqual(capture.fact.content, b"")
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                capture.fact.state = "retained"
        finally:
            capture.close()
            sidecars.close()
            descriptors.close()

    def test_valid_pair_retains_one_main_parent_master_in_either_order(self):
        import unittest.mock as mock

        pm = processing_module
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                prepared = self._prepare()
                (
                    descriptors,
                    assessments,
                    _vacancy,
                    sidecars,
                    journals,
                    _main_path,
                    _vacancy_path,
                    main_journal,
                    vacancy_journal,
                    master,
                    _content,
                ) = prepared
                entries = (str(main_journal), str(vacancy_journal))
                if reverse:
                    entries = tuple(reversed(entries))
                    content = (
                        os.fsencode(entries[0])
                        + b"\x00"
                        + os.fsencode(entries[1])
                        + b"\x00"
                    )
                    master.write_bytes(content)
                    os.chmod(master, 0o600)
                baseline = len(os.listdir("/dev/fd"))
                real_open = pm.os.open
                master_opens = []

                def exact_master_open(path, flags, *args, **kwargs):
                    if path == master.name:
                        master_opens.append(
                            (path, flags, kwargs.get("dir_fd"))
                        )
                    return real_open(path, flags, *args, **kwargs)

                capture = None
                try:
                    with mock.patch.object(
                        pm.os, "open", side_effect=exact_master_open
                    ):
                        capture = pm._MasterJournalCapture(
                            sidecars, journals
                        )
                    self.assertEqual(len(master_opens), 1)
                    self.assertEqual(master_opens[0][0], master.name)
                    self.assertEqual(
                        master_opens[0][2], assessments.parent.fd
                    )
                    self.assertTrue(master_opens[0][1] & os.O_NOFOLLOW)
                    self.assertTrue(master_opens[0][1] & os.O_NONBLOCK)
                    self.assertEqual(capture.fact.state, "retained")
                    self.assertEqual(capture.fact.path, str(master))
                    self.assertEqual(set(capture.fact.entries), set(entries))
                    self.assertEqual(capture.fact.content, master.read_bytes())
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline + 1)
                    self.assertNotIn(
                        "fd",
                        {field.name for field in dataclasses.fields(capture.fact)},
                    )
                finally:
                    if capture is not None:
                        capture.close()
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline)
                    sidecars.close()
                    descriptors.close()

    def test_one_or_mismatched_pointer_refuses_before_master_open(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in ("one", "mismatched"):
            with self.subTest(variant=variant):
                prepared = self._prepare()
                (
                    descriptors,
                    _assessments,
                    _vacancy,
                    sidecars,
                    journals,
                    _main_path,
                    _vacancy_path,
                    _main_journal,
                    _vacancy_journal,
                    master,
                    _content,
                ) = prepared
                if variant == "one":
                    altered = dataclasses.replace(
                        journals[1], pointer=pm._PointerTail("none", None),
                        pointer_path=None
                    )
                else:
                    altered = dataclasses.replace(
                        journals[1], pointer_path=str(master.parent / "other-master")
                    )
                supplied = (journals[0], altered)
                opens = []
                real_open = pm.os.open

                def forbid_master_open(path, flags, *args, **kwargs):
                    if path == master.name:
                        opens.append(path)
                        raise AssertionError("incoherent pointers reached open")
                    return real_open(path, flags, *args, **kwargs)

                try:
                    with mock.patch.object(
                        pm.os, "open", side_effect=forbid_master_open
                    ):
                        with self.assertRaises(pm.ProcessingRefused) as caught:
                            pm._MasterJournalCapture(sidecars, supplied)
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                    self.assertEqual(opens, [])
                finally:
                    sidecars.close()
                    descriptors.close()

    def test_missing_and_unsafe_master_objects_refuse_reason15(self):
        pm = processing_module
        variants = (
            "missing",
            "symlink",
            "hardlink",
            "mode_0644",
            "mode_0664",
            "fifo",
            "directory",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                prepared = self._prepare(create_master=False)
                (
                    descriptors,
                    _assessments,
                    _vacancy,
                    sidecars,
                    journals,
                    _main_path,
                    _vacancy_path,
                    _main_journal,
                    _vacancy_journal,
                    master,
                    content,
                ) = prepared
                target = master.parent / "target"
                if variant == "symlink":
                    target.write_bytes(content)
                    os.chmod(target, 0o600)
                    master.symlink_to(target)
                elif variant == "hardlink":
                    target.write_bytes(content)
                    os.chmod(target, 0o600)
                    os.link(target, master)
                elif variant == "fifo":
                    os.mkfifo(master, 0o600)
                elif variant == "directory":
                    master.mkdir()
                    os.chmod(master, 0o700)
                elif variant != "missing":
                    master.write_bytes(content)
                    os.chmod(
                        master,
                        0o644 if variant == "mode_0644" else 0o664,
                    )
                try:
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        pm._MasterJournalCapture(sidecars, journals)
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                finally:
                    sidecars.close()
                    descriptors.close()

    def test_wrong_owner_prestat_and_regular_to_fifo_swap_never_block(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in ("wrong_owner", "fifo_swap"):
            with self.subTest(variant=variant):
                prepared = self._prepare()
                (
                    descriptors,
                    assessments,
                    _vacancy,
                    sidecars,
                    journals,
                    _main_path,
                    _vacancy_path,
                    _main_journal,
                    _vacancy_journal,
                    master,
                    _content,
                ) = prepared
                real_stat = pm.os.stat
                real_open = pm.os.open
                baseline = len(os.listdir("/dev/fd"))
                master_opens = []

                def injected_stat(path, *args, **kwargs):
                    result = real_stat(path, *args, **kwargs)
                    if (
                        variant == "wrong_owner"
                        and path == master.name
                        and kwargs.get("dir_fd") == assessments.parent.fd
                    ):
                        values = list(result)
                        values[4] = os.getuid() + 1
                        return os.stat_result(values)
                    return result

                def injected_open(path, flags, *args, **kwargs):
                    if (
                        path == master.name
                        and kwargs.get("dir_fd") == assessments.parent.fd
                    ):
                        master_opens.append(flags)
                        if variant == "wrong_owner":
                            raise AssertionError(
                                "wrong-owner master reached os.open"
                            )
                        master.unlink()
                        os.mkfifo(master, 0o600)
                    return real_open(path, flags, *args, **kwargs)

                started = time.monotonic()
                try:
                    with mock.patch.object(
                        pm.os, "stat", side_effect=injected_stat
                    ), mock.patch.object(
                        pm.os, "open", side_effect=injected_open
                    ):
                        with self.assertRaises(pm.ProcessingRefused) as caught:
                            pm._MasterJournalCapture(sidecars, journals)
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                    self.assertLess(time.monotonic() - started, 1.0)
                    if variant == "wrong_owner":
                        self.assertEqual(master_opens, [])
                    else:
                        self.assertEqual(len(master_opens), 1)
                        self.assertTrue(master_opens[0] & os.O_NONBLOCK)
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline)
                finally:
                    sidecars.close()
                    descriptors.close()

    def test_oversize_master_refuses_before_read(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare()
        (
            descriptors,
            _assessments,
            _vacancy,
            sidecars,
            journals,
            _main_path,
            _vacancy_path,
            _main_journal,
            _vacancy_journal,
            master,
            _content,
        ) = prepared
        limit = pm._master_journal_size_limit(sidecars.path_maxima[0])
        master.write_bytes(b"x" * (limit + 1))
        os.chmod(master, 0o600)
        reads = []
        real_pread = pm.os.pread

        def no_master_read(fd, length, offset):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (
                os.stat(master).st_dev,
                os.stat(master).st_ino,
            ):
                reads.append((length, offset))
            return real_pread(fd, length, offset)

        try:
            with mock.patch.object(pm.os, "pread", side_effect=no_master_read):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._MasterJournalCapture(sidecars, journals)
            self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
            self.assertEqual(reads, [])
        finally:
            sidecars.close()
            descriptors.close()

    def test_master_content_matrix_refuses_every_nonexact_shape(self):
        pm = processing_module
        seed = self._prepare()
        (
            seed_descriptors,
            _seed_assessments,
            _seed_vacancy,
            seed_sidecars,
            _seed_journals,
            _seed_main_path,
            _seed_vacancy_path,
            seed_main_journal,
            seed_vacancy_journal,
            _seed_master,
            _seed_content,
        ) = seed
        main_bytes = os.fsencode(seed_main_journal)
        vacancy_bytes = os.fsencode(seed_vacancy_journal)
        main_parent = os.fsencode(seed_main_journal.parent)
        vacancy_parent = os.fsencode(seed_vacancy_journal.parent)
        seed_sidecars.close()
        seed_descriptors.close()
        variants = (
            ("missing terminator", main_bytes + b"\x00" + vacancy_bytes),
            ("empty", main_bytes + b"\x00\x00"),
            ("extra", main_bytes + b"\x00" + vacancy_bytes + b"\x00extra"),
            ("duplicate", main_bytes + b"\x00" + main_bytes + b"\x00"),
            (
                "wrong set",
                main_bytes + b"\x00" + main_parent + b"/other-journal\x00",
            ),
            ("nonutf8", main_bytes + b"\x00" + vacancy_parent + b"/\xff\x00"),
            ("relative", main_bytes + b"\x00relative-journal\x00"),
            (
                "dot",
                main_bytes + b"\x00" + vacancy_parent + b"/./x-journal\x00",
            ),
            (
                "dotdot",
                main_bytes + b"\x00" + vacancy_parent + b"/../x-journal\x00",
            ),
            (
                "nested",
                main_bytes + b"\x00" + vacancy_parent + b"/nested/x-journal\x00",
            ),
            (
                "alias",
                main_bytes + b"\x00" + vacancy_parent + b"//x-journal\x00",
            ),
        )
        for label, template in variants:
            with self.subTest(label=label):
                prepared = self._prepare()
                (
                    descriptors,
                    _assessments,
                    _vacancy,
                    sidecars,
                    journals,
                    _main_path,
                    _vacancy_path,
                    main_journal,
                    vacancy_journal,
                    master,
                    _content,
                ) = prepared
                content = template.replace(
                    main_bytes, os.fsencode(main_journal)
                ).replace(vacancy_bytes, os.fsencode(vacancy_journal))
                master.write_bytes(content)
                os.chmod(master, 0o600)
                try:
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        pm._MasterJournalCapture(sidecars, journals)
                    self.assertEqual(
                        caught.exception.reason, pm.REASON_ATOMIC_MODE
                    )
                finally:
                    sidecars.close()
                    descriptors.close()

    def test_mid_read_master_identity_size_and_name_churn_are_fd_stable(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in ("identity", "size", "name"):
            with self.subTest(variant=variant):
                prepared = self._prepare()
                (
                    descriptors,
                    _assessments,
                    _vacancy,
                    sidecars,
                    journals,
                    _main_path,
                    _vacancy_path,
                    _main_journal,
                    _vacancy_journal,
                    master,
                    content,
                ) = prepared
                master_info = os.stat(master)
                baseline = len(os.listdir("/dev/fd"))
                real_pread = pm.os.pread
                injected = False

                def faulted_pread(fd, length, offset):
                    nonlocal injected
                    info = os.fstat(fd)
                    if (
                        not injected
                        and (info.st_dev, info.st_ino)
                        == (master_info.st_dev, master_info.st_ino)
                    ):
                        injected = True
                        result = real_pread(fd, length, offset)
                        if variant == "identity":
                            replacement = master.parent / "replacement"
                            replacement.write_bytes(content)
                            os.chmod(replacement, 0o600)
                            os.replace(replacement, master)
                        elif variant == "size":
                            with master.open("ab") as stream:
                                stream.write(b"growth")
                        else:
                            master.unlink()
                        return result
                    return real_pread(fd, length, offset)

                try:
                    with mock.patch.object(
                        pm.os, "pread", side_effect=faulted_pread
                    ):
                        with self.assertRaises(pm._SidecarChurn):
                            pm._MasterJournalCapture(sidecars, journals)
                    self.assertTrue(injected)
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline)
                finally:
                    sidecars.close()
                    descriptors.close()

    def test_exact_bounded_master_read_and_repeated_fd_stability(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare()
        (
            descriptors,
            _assessments,
            _vacancy,
            sidecars,
            journals,
            _main_path,
            _vacancy_path,
            _main_journal,
            _vacancy_journal,
            master,
            content,
        ) = prepared
        master_info = os.stat(master)
        real_pread = pm.os.pread
        master_reads = []

        def observed_pread(fd, length, offset):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (
                master_info.st_dev,
                master_info.st_ino,
            ):
                master_reads.append((length, offset))
            return real_pread(fd, length, offset)

        capture = None
        baseline = len(os.listdir("/dev/fd"))
        try:
            with mock.patch.object(
                pm.os, "pread", side_effect=observed_pread
            ):
                capture = pm._MasterJournalCapture(sidecars, journals)
            self.assertEqual(master_reads, [(len(content), 0), (1, len(content))])
            capture.close()
            capture = None
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)
            for _ in range(50):
                current = pm._MasterJournalCapture(sidecars, journals)
                self.assertEqual(len(os.listdir("/dev/fd")), baseline + 1)
                current.close()
                self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        finally:
            if capture is not None:
                capture.close()
            sidecars.close()
            descriptors.close()

    def test_master_close_ambiguity_is_sticky_and_never_retries_fd(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare()
        (
            descriptors,
            _assessments,
            _vacancy,
            sidecars,
            journals,
            _main_path,
            _vacancy_path,
            _main_journal,
            _vacancy_journal,
            _master,
            _content,
        ) = prepared
        capture = pm._MasterJournalCapture(sidecars, journals)
        real_close = os.close
        calls = []

        def ambiguous_close(fd):
            calls.append(fd)
            raise OSError(errno.EIO, "injected close ambiguity")

        with mock.patch.object(pm.os, "close", side_effect=ambiguous_close):
            with self.assertRaises(pm.ProcessingRefused) as first:
                capture.close()
            with self.assertRaises(pm.ProcessingRefused) as second:
                capture.close()
            self.assertIs(second.exception, first.exception)
        self.assertEqual(len(calls), 1)
        real_close(calls[0])
        sidecars.close()
        descriptors.close()


class StageDPart3C2FilesystemEpochTests(TempRootTestCase):
    MAGIC = StageDPart3C2MasterJournalCaptureTests.MAGIC

    def _manual_pair(self, *, journal=None):
        return StageDPart3C2SidecarHardeningTests._manual_pair(self, journal=journal)

    def _header(self):
        return StageDPart3C2MasterJournalCaptureTests._header(self)

    def _journal_bytes(self, pointer_path, *, size=1024):
        return StageDPart3C2MasterJournalCaptureTests._journal_bytes(
            self, pointer_path, size=size
        )

    def _prepare(self, **kwargs):
        return StageDPart3C2MasterJournalCaptureTests._prepare(self, **kwargs)

    def test_stable_cold_and_paired_master_epochs_are_frozen_and_fd_free(self):
        pm = processing_module
        for variant in ("cold", "paired"):
            with self.subTest(variant=variant):
                if variant == "cold":
                    descriptors, assessments, vacancy, _main, _vacancy = (
                        self._manual_pair()
                    )
                    expected_master = "none"
                    expected_master_identity = None
                else:
                    prepared = self._prepare()
                    (
                        descriptors,
                        assessments,
                        vacancy,
                        sidecars,
                        _journals,
                        _main,
                        _vacancy,
                        _main_journal,
                        _vacancy_journal,
                        master,
                        _content,
                    ) = prepared
                    sidecars.close()
                    expected_master = "retained"
                    expected_master_identity = pm._identity(os.stat(master))
                baseline = len(os.listdir("/dev/fd"))
                try:
                    facts = pm._stabilize_filesystem_epoch(
                        descriptors, assessments, vacancy
                    )
                    self.assertEqual(len(facts.sidecars), 6)
                    self.assertEqual(len(facts.path_maxima), 2)
                    self.assertEqual(len(facts.journals), 2)
                    self.assertEqual(facts.master.state, expected_master)
                    self.assertEqual(facts.master_identity, expected_master_identity)
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline)
                    for node in (
                        facts,
                        *facts.sidecars,
                        *facts.journals,
                        facts.master,
                    ):
                        self.assertNotIn(
                            "fd",
                            {field.name for field in dataclasses.fields(node)},
                        )
                    with self.assertRaises(dataclasses.FrozenInstanceError):
                        facts.master = pm._MasterJournalObservation(
                            "none", None, None, (), b""
                        )
                    with self.assertRaises(dataclasses.FrozenInstanceError):
                        facts.master_identity = None
                finally:
                    descriptors.close()

    def test_same_byte_master_inode_substitution_before_publication_churns(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare()
        (
            descriptors,
            assessments,
            vacancy,
            sidecars,
            _journals,
            _main,
            _vacancy,
            _main_journal,
            _vacancy_journal,
            master,
            content,
        ) = prepared
        sidecars.close()
        old_identity = pm._identity(os.stat(master))
        replacement = master.parent / "same-byte-master-replacement"
        replacement.write_bytes(content)
        os.chmod(replacement, 0o600)
        real_observe = pm._SidecarPairCapture.observe_journals
        calls = 0

        def replace_after_final_journal_read(owner):
            nonlocal calls
            calls += 1
            result = real_observe(owner)
            if calls == 7:
                os.replace(replacement, master)
            return result

        baseline = len(os.listdir("/dev/fd"))
        try:
            with (
                mock.patch.object(
                    pm._SidecarPairCapture,
                    "observe_journals",
                    autospec=True,
                    side_effect=replace_after_final_journal_read,
                ),
                self.assertRaises(pm._SidecarChurn),
            ):
                pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            self.assertGreaterEqual(calls, 8)
            self.assertNotEqual(old_identity, pm._identity(os.stat(master)))
            self.assertEqual(master.read_bytes(), content)
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        finally:
            descriptors.close()

    def test_master_identity_mismatch_restarts_before_stabilizing(self):
        import unittest.mock as mock

        pm = processing_module
        prepared = self._prepare()
        (
            descriptors,
            assessments,
            vacancy,
            sidecars,
            _journals,
            _main,
            _vacancy,
            _main_journal,
            _vacancy_journal,
            _master,
            _content,
        ) = prepared
        sidecars.close()
        try:
            exact = pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            self.assertIsNotNone(exact.master_identity)
            changed_identity = list(exact.master_identity)
            changed_identity[1] += 1
            changed = dataclasses.replace(
                exact, master_identity=tuple(changed_identity)
            )
            self.assertEqual(changed.master, exact.master)
            with mock.patch.object(
                pm,
                "_capture_filesystem_epoch",
                side_effect=(exact, changed, exact, exact),
            ) as capture:
                result = pm._stabilize_filesystem_epoch(
                    descriptors, assessments, vacancy
                )
            self.assertEqual(result, exact)
            self.assertEqual(capture.call_count, 4)
        finally:
            descriptors.close()

    def test_retained_database_descriptor_and_name_size_drift_are_reason5(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in ("descriptor", "name"):
            with self.subTest(variant=variant):
                descriptors, assessments, _vacancy, main, _vacancy_path = (
                    self._manual_pair()
                )
                try:
                    self.assertEqual(assessments.size, os.stat(main).st_size)
                    if variant == "descriptor":
                        with main.open("ab") as stream:
                            stream.write(b"growth")
                        context = contextlib.nullcontext()
                    else:
                        real_stat = pm.os.stat
                        changed = list(real_stat(main))
                        changed[6] += 1
                        changed_info = os.stat_result(changed)

                        def changed_name(path, *args, **kwargs):
                            if (
                                path == assessments.name
                                and kwargs.get("dir_fd") == assessments.parent.fd
                            ):
                                return changed_info
                            return real_stat(path, *args, **kwargs)

                        context = mock.patch.object(
                            pm.os, "stat", side_effect=changed_name
                        )
                    with context, self.assertRaises(pm.ProcessingRefused) as caught:
                        assessments.revalidate()
                    self.assertEqual(caught.exception.reason, pm.REASON_CONFIG_DATABASE)
                    self.assertIn("size", str(caught.exception))
                finally:
                    descriptors.close()

    def test_fact_mismatch_and_churn_restart_then_return_stable_epoch(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, _main, _vacancy_path = self._manual_pair()
        try:
            exact = pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            changed = dataclasses.replace(
                exact,
                path_maxima=(exact.path_maxima[0], exact.path_maxima[1] + 1),
            )
            cases = (
                ([exact, changed, exact, exact], 4),
                ([pm._SidecarChurn("first"), exact, exact], 3),
                ([exact, pm._SidecarChurn("second"), exact, exact], 4),
            )
            for effects, expected_calls in cases:
                with (
                    self.subTest(effects=len(effects)),
                    mock.patch.object(
                        pm,
                        "_capture_filesystem_epoch",
                        side_effect=effects,
                    ) as capture,
                ):
                    result = pm._stabilize_filesystem_epoch(
                        descriptors, assessments, vacancy
                    )
                    self.assertEqual(result, exact)
                    self.assertEqual(capture.call_count, expected_calls)
        finally:
            descriptors.close()

    def test_safe_constructor_window_replacement_is_churn_and_closes_fd(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, main, _vacancy_path = self._manual_pair(
            journal=b"private-journal"
        )
        journal = main.parent / (main.name + "-journal")
        replacement = main.parent / "replacement"
        replacement.write_bytes(b"private-journal")
        os.chmod(replacement, 0o600)
        real_open = pm.os.open
        baseline = len(os.listdir("/dev/fd"))
        replaced = False

        def replace_before_open(path, flags, *args, **kwargs):
            nonlocal replaced
            if (
                not replaced
                and path == journal.name
                and kwargs.get("dir_fd") == assessments.parent.fd
            ):
                replaced = True
                os.replace(replacement, journal)
            return real_open(path, flags, *args, **kwargs)

        try:
            with (
                mock.patch.object(pm.os, "open", side_effect=replace_before_open),
                self.assertRaises(pm._SidecarChurn),
            ):
                pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            self.assertTrue(replaced)
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        finally:
            descriptors.close()

    def test_perpetual_churn_and_mismatch_share_one_fixed_deadline(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, _main, _vacancy_path = self._manual_pair()
        try:
            exact = pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            changed = dataclasses.replace(
                exact,
                path_maxima=(exact.path_maxima[0], exact.path_maxima[1] + 1),
            )
            cases = (
                (
                    [pm._SidecarChurn("one"), pm._SidecarChurn("two")],
                    [100.0, 129.0, 130.0],
                    2,
                ),
                ([exact, changed, exact], [100.0, 101.0, 102.0, 130.0], 3),
            )
            for effects, clock_values, calls in cases:
                with (
                    self.subTest(calls=calls),
                    mock.patch.object(
                        pm,
                        "_capture_filesystem_epoch",
                        side_effect=effects,
                    ) as capture,
                    mock.patch.object(
                        pm.time,
                        "monotonic",
                        side_effect=clock_values,
                    ) as monotonic,
                ):
                    with self.assertRaises(pm.ProcessingRefused) as caught:
                        pm._stabilize_filesystem_epoch(
                            descriptors, assessments, vacancy
                        )
                    self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
                    self.assertIn("fixed 30-second", str(caught.exception))
                    self.assertEqual(capture.call_count, calls)
                    self.assertEqual(monotonic.call_count, len(clock_values))
        finally:
            descriptors.close()

    def test_unsafe_sidecar_and_master_refuse_immediately_without_retry(self):
        import unittest.mock as mock

        pm = processing_module
        for variant in ("sidecar", "master"):
            with self.subTest(variant=variant):
                if variant == "sidecar":
                    descriptors, assessments, vacancy, main, _vacancy_path = (
                        self._manual_pair()
                    )
                    journal = main.parent / (main.name + "-journal")
                    journal.write_bytes(b"unsafe")
                    os.chmod(journal, 0o644)
                else:
                    prepared = self._prepare(master_content=b"malformed")
                    (
                        descriptors,
                        assessments,
                        vacancy,
                        sidecars,
                        _journals,
                        _main,
                        _vacancy,
                        _main_journal,
                        _vacancy_journal,
                        _master,
                        _content,
                    ) = prepared
                    sidecars.close()
                try:
                    with (
                        mock.patch.object(
                            pm,
                            "_capture_filesystem_epoch",
                            wraps=pm._capture_filesystem_epoch,
                        ) as capture,
                        self.assertRaises(pm.ProcessingRefused) as caught,
                    ):
                        pm._stabilize_filesystem_epoch(
                            descriptors, assessments, vacancy
                        )
                    self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
                    self.assertEqual(capture.call_count, 1)
                finally:
                    descriptors.close()

    def test_database_drift_refuses_immediately_without_epoch_rebinding(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, main, _vacancy_path = self._manual_pair()
        with main.open("ab") as stream:
            stream.write(b"drift")
        try:
            with (
                mock.patch.object(
                    pm,
                    "_capture_filesystem_epoch",
                    wraps=pm._capture_filesystem_epoch,
                ) as capture,
                self.assertRaises(pm.ProcessingRefused) as caught,
            ):
                pm._stabilize_filesystem_epoch(descriptors, assessments, vacancy)
            self.assertEqual(caught.exception.reason, pm.REASON_CONFIG_DATABASE)
            self.assertEqual(capture.call_count, 1)
        finally:
            descriptors.close()

    def test_epoch_cleanup_is_master_first_and_close_ambiguity_overrides_churn(self):
        pm = processing_module

        class Owner:
            def __init__(self, label, order, failure=None):
                self.label = label
                self.order = order
                self.failure = failure

            def close(self):
                self.order.append(self.label)
                if self.failure is not None:
                    raise self.failure

        for failing in ("master", "sidecars"):
            with self.subTest(failing=failing):
                order = []
                master = Owner(
                    "master",
                    order,
                    OSError(errno.EIO, "master close") if failing == "master" else None,
                )
                sidecars = Owner(
                    "sidecars",
                    order,
                    OSError(errno.EIO, "sidecar close")
                    if failing == "sidecars"
                    else None,
                )
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._close_filesystem_epoch_owners(
                        master, sidecars, pm._SidecarChurn("weaker churn")
                    )
                self.assertEqual(order, ["master", "sidecars"])
                self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
                self.assertIn("ambiguous", str(caught.exception))

    def test_real_epoch_success_closes_master_before_sidecars(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, _main, _vacancy_path = self._manual_pair()
        order = []
        real_master_close = pm._MasterJournalCapture.close
        real_sidecar_close = pm._SidecarPairCapture.close

        def close_master(owner):
            order.append("master")
            return real_master_close(owner)

        def close_sidecars(owner):
            order.append("sidecars")
            return real_sidecar_close(owner)

        try:
            with (
                mock.patch.object(
                    pm._MasterJournalCapture,
                    "close",
                    autospec=True,
                    side_effect=close_master,
                ),
                mock.patch.object(
                    pm._SidecarPairCapture,
                    "close",
                    autospec=True,
                    side_effect=close_sidecars,
                ),
            ):
                facts = pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            self.assertEqual(facts.master.state, "none")
            self.assertEqual(order, ["master", "sidecars"])
        finally:
            descriptors.close()

    def test_success_churn_and_refusal_campaigns_keep_fd_baseline(self):
        import unittest.mock as mock

        pm = processing_module
        descriptors, assessments, vacancy, main, _vacancy_path = self._manual_pair()
        baseline = len(os.listdir("/dev/fd"))
        for _ in range(50):
            pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
            self.assertEqual(len(os.listdir("/dev/fd")), baseline)

        journal = main.parent / (main.name + "-journal")
        journal.write_bytes(b"private")
        os.chmod(journal, 0o600)
        try:
            with mock.patch.object(
                pm,
                "_MasterJournalCapture",
                side_effect=pm._SidecarChurn("injected safe churn"),
            ):
                for _ in range(50):
                    with self.assertRaises(pm._SidecarChurn):
                        pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
                    self.assertEqual(len(os.listdir("/dev/fd")), baseline)

            os.chmod(journal, 0o644)
            for _ in range(50):
                with self.assertRaises(pm.ProcessingRefused) as caught:
                    pm._capture_filesystem_epoch(descriptors, assessments, vacancy)
                self.assertEqual(caught.exception.reason, pm.REASON_ATOMIC_MODE)
                self.assertEqual(len(os.listdir("/dev/fd")), baseline)
        finally:
            descriptors.close()





class StageDPart3C2Increment1Tests(unittest.TestCase):
    """C2 Increment 1: PRAGMA admission + reason-14 plan + staged score."""

    class _Cursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class _ScriptedConnection:
        def __init__(self, script):
            self.script = {query: list(results) for query, results in script.items()}
            self.statements = []

        def execute(self, query, *args):
            del args
            self.statements.append(query)
            results = self.script.get(query)
            outcome = [] if results is None else results.pop(0)
            if isinstance(outcome, sqlite3.Error):
                raise outcome
            return StageDPart3C2Increment1Tests._Cursor(outcome)

    def _make_two_db_connection(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        main_path = os.path.join(tmp, "assessments.sqlite3")
        vac_path = os.path.join(tmp, "vacancies.sqlite3")
        main_owner = sqlite3.connect(main_path)
        main_owner.executescript(research_store_module.SCHEMA)
        main_owner.close()
        from market_aligner.state import vacancies as vacancies_module

        vacancy_owner = sqlite3.connect(vac_path)
        vacancy_owner.executescript(vacancies_module.SCHEMA)
        vacancy_owner.close()
        conn = sqlite3.connect(main_path)
        conn.execute("ATTACH DATABASE ? AS vacancy", (vac_path,))
        self.addCleanup(conn.close)
        return conn, main_path, vac_path

    def _pragma_script(self):
        database_list = [(0, "main", "/main"), (2, "vacancy", "/vacancy")]
        return {
            "PRAGMA database_list": [database_list, database_list],
            "PRAGMA main.wal_checkpoint(TRUNCATE)": [[(0, -1, -1)]],
            "PRAGMA vacancy.wal_checkpoint(TRUNCATE)": [[(0, -1, -1)]],
            "PRAGMA main.journal_mode=DELETE": [[("delete",)]],
            "PRAGMA vacancy.journal_mode=DELETE": [[("delete",)]],
            "PRAGMA main.journal_mode": [[("delete",)]],
            "PRAGMA vacancy.journal_mode": [[("delete",)]],
            "PRAGMA main.synchronous": [[(2,)]],
            "PRAGMA vacancy.synchronous": [[(2,)]],
            "PRAGMA foreign_keys": [[(1,)]],
            "PRAGMA busy_timeout": [[(30000,)]],
        }

    def _result(self):
        from market_aligner.assessment.scoring import ScoringParams

        return processing_module.ScoreResult(
            profile_id="prf_" + "a" * 32,
            job_key="boards.example:j-1",
            track="backend",
            fit=0.42,
            opportunity=0.555,
            final=48.75,
            fit_status=processing_module.FitStatus.UNCALIBRATED,
            parameters_hash=ScoringParams().parameters_hash,
            fit_subscores={
                "interest": 0.4,
                "demonstrated_skill": 0.5,
                "market_readiness": 0.3,
                "technical_alignment": 0.6,
                "evidence_match": 0.5,
            },
            opportunity_subscores={
                "market_demand": 0.0,
                "accessibility": 1.0,
                "growth_potential": 0.0,
            },
        )

    def _plan_kwargs(self, result=None, *, accepted_at="2026-08-25T12:00:00Z"):
        result = self._result() if result is None else result
        normalized_json = '{"company":"Example","title":"Engineer"}'
        return {
            "result_obj": result,
            "url": "https://example.test/job",
            "title": "Engineer",
            "company": "Example",
            "extraction_confidence": 0.9,
            "job_key": result.job_key,
            "profile_id": result.profile_id,
            "normalized_json": normalized_json,
            "normalized_json_sha256": hashlib.sha256(
                normalized_json.encode("utf-8")
            ).hexdigest(),
            "accepted_at": accepted_at,
        }

    def _score_facts(self, node=None, *, raw_bytes=None, expected=None):
        result = self._result()
        if node is None:
            node = dataclasses.asdict(result)
        if expected is None:
            expected = processing_module.ExpectedScoreFacts(
                profile_id=result.profile_id,
                job_key=result.job_key,
                track=result.track,
                fit=result.fit,
                opportunity=result.opportunity,
                final=result.final,
                fit_status=result.fit_status.value,
                parameters_hash=result.parameters_hash,
                fit_subscores=tuple(sorted(result.fit_subscores.items())),
                opportunity_subscores=tuple(
                    sorted(result.opportunity_subscores.items())
                ),
            )

        class Facts:
            pass

        facts = Facts()
        facts.expected_score = expected
        facts.expected_score_canonical = (
            processing_module.canonical_json(node).encode("utf-8")
            if raw_bytes is None
            else raw_bytes
        )
        return facts

    def test_setup_positive(self) -> None:
        conn, _, _ = self._make_two_db_connection()
        processing_module.setup_transaction_sqlite(conn)
        self.assertEqual(conn.execute("PRAGMA main.journal_mode").fetchone(), ("delete",))
        self.assertEqual(
            conn.execute("PRAGMA vacancy.journal_mode").fetchone(), ("delete",)
        )
        self.assertEqual(conn.execute("PRAGMA main.synchronous").fetchone(), (2,))
        self.assertEqual(conn.execute("PRAGMA vacancy.synchronous").fetchone(), (2,))
        self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone(), (1,))
        self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone(), (30000,))

    def test_setup_database_list_rejects_every_nonexact_shape(self) -> None:
        variants = (
            [],
            [(0, "main", "/main")],
            [(0, "main", "/main"), (2, "other", "/vacancy")],
            [(0, "vacancy", "/vacancy"), (2, "main", "/main")],
            [[0, "main", "/main"], (2, "vacancy", "/vacancy")],
            [(False, "main", "/main"), (2, "vacancy", "/vacancy")],
            [(0, "main"), (2, "vacancy", "/vacancy")],
            "not-a-list",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                script = self._pragma_script()
                script["PRAGMA database_list"] = [variant]
                connection = self._ScriptedConnection(script)
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.setup_transaction_sqlite(connection)
                self.assertEqual(
                    caught.exception.reason, processing_module.REASON_ATOMIC_MODE
                )

    def test_setup_checkpoint_rejects_every_nonexact_result(self) -> None:
        variants = (
            [],
            [(0, -1, -1), (0, -1, -1)],
            [[0, -1, -1]],
            [(0, -1)],
            [(0, -1, -1, 0)],
            [(False, -1, -1)],
            [(-1, -1, -1)],
            [(1, 0, 0)],
            [(0, -2, -1)],
            [(0, -1, -2)],
            [(0, "-1", -1)],
        )
        for variant in variants:
            with self.subTest(variant=variant):
                script = self._pragma_script()
                script["PRAGMA main.wal_checkpoint(TRUNCATE)"] = [variant]
                connection = self._ScriptedConnection(script)
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.setup_transaction_sqlite(connection)
                self.assertEqual(
                    caught.exception.reason, processing_module.REASON_ATOMIC_MODE
                )

    def test_setup_rejects_wrong_direct_and_readback_values(self) -> None:
        cases = {
            "PRAGMA main.journal_mode=DELETE": [[], [("wal",)], [["delete"]]],
            "PRAGMA main.journal_mode": [[], [("wal",)], [("delete", "extra")]],
            "PRAGMA main.synchronous": [[], [(1,)], [(True,)]],
            "PRAGMA foreign_keys": [[], [(0,)], [(True,)]],
            "PRAGMA busy_timeout": [[], [(0,)], [(True,)]],
        }
        for query, variants in cases.items():
            for variant in variants:
                with self.subTest(query=query, variant=variant):
                    script = self._pragma_script()
                    script[query] = [variant]
                    connection = self._ScriptedConnection(script)
                    with self.assertRaises(
                        processing_module.ProcessingRefused
                    ) as caught:
                        processing_module.setup_transaction_sqlite(connection)
                    self.assertEqual(
                        caught.exception.reason, processing_module.REASON_ATOMIC_MODE
                    )

    def test_setup_maps_sqlite_errors_without_shape_exceptions(self) -> None:
        for query in (
            "PRAGMA database_list",
            "PRAGMA main.wal_checkpoint(TRUNCATE)",
            "PRAGMA main.journal_mode=DELETE",
            "PRAGMA main.journal_mode",
            "PRAGMA main.synchronous=FULL",
            "PRAGMA main.synchronous",
            "PRAGMA foreign_keys=ON",
            "PRAGMA foreign_keys",
            "PRAGMA busy_timeout=30000",
            "PRAGMA busy_timeout",
        ):
            with self.subTest(query=query):
                script = self._pragma_script()
                script[query] = [sqlite3.OperationalError("injected")]
                connection = self._ScriptedConnection(script)
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.setup_transaction_sqlite(connection)
                self.assertEqual(
                    caught.exception.reason, processing_module.REASON_ATOMIC_MODE
                )

    def test_setup_no_ddl_dml(self) -> None:
        connection = self._ScriptedConnection(self._pragma_script())
        processing_module.setup_transaction_sqlite(connection)
        forbidden = ("BEGIN", "COMMIT", "ROLLBACK", "CREATE", "INSERT", "UPDATE")
        for statement in connection.statements:
            self.assertFalse(statement.strip().upper().startswith(forbidden), statement)

    def test_plan_absent_all_insert_required(self) -> None:
        conn, _, _ = self._make_two_db_connection()
        kwargs = self._plan_kwargs()
        statements = []
        conn.set_trace_callback(statements.append)
        plan = processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual(plan.normalized_action, "insert")
        self.assertEqual(plan.normalized_at, kwargs["accepted_at"])
        self.assertEqual(plan.score_plan.action, "insert")
        self.assertEqual(plan.event_action, "insert_required")
        self.assertTrue(all(row.lstrip().upper().startswith("SELECT") for row in statements))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.normalized_action = "reuse"

    def test_plan_normalized_reuse_preserves_timestamp_and_conflicts_exactly(self) -> None:
        conn, _, _ = self._make_two_db_connection()
        kwargs = self._plan_kwargs()
        durable = "2026-08-20T10:00:00Z"
        conn.execute(
            "INSERT INTO vacancy.normalised_jobs(key,normalized_json,normalized_at) "
            "VALUES(?,?,?)",
            (kwargs["job_key"], kwargs["normalized_json"], durable),
        )
        plan = processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual((plan.normalized_action, plan.normalized_at), ("reuse", durable))
        conn.execute(
            "UPDATE vacancy.normalised_jobs SET normalized_json='different' WHERE key=?",
            (kwargs["job_key"],),
        )
        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual(caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT)

    def test_plan_rejects_hash_timestamp_identity_and_malformed_row_before_writes(self) -> None:
        import unittest.mock as mock

        conn, _, _ = self._make_two_db_connection()
        cases = (
            {"normalized_json_sha256": "0" * 64},
            {"normalized_json_sha256": True},
            {"accepted_at": "2026-08-25 12:00:00"},
            {"profile_id": "prf_" + "b" * 32},
            {"job_key": "boards.example:other"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                kwargs = self._plan_kwargs()
                kwargs.update(changes)
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.plan_reason14_projections(conn, **kwargs)
                self.assertEqual(
                    caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT
                )
        kwargs = self._plan_kwargs()
        with mock.patch.object(
            processing_module, "read_normalized_job", return_value=("text", 123)
        ):
            with self.assertRaises(processing_module.ProcessingRefused) as caught:
                processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual(caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT)

    def test_plan_score_reuse_preserves_durable_timestamps_and_conflict_maps(self) -> None:
        conn, _, _ = self._make_two_db_connection()
        kwargs = self._plan_kwargs(accepted_at="2026-08-25T12:00:00Z")
        first_time = "2026-08-20T10:00:00Z"
        research_store_module.cas_accepted_score(
            conn,
            result=kwargs["result_obj"],
            url=kwargs["url"],
            title=kwargs["title"],
            company=kwargs["company"],
            extraction_confidence=kwargs["extraction_confidence"],
            accepted_at=first_time,
        )
        plan = processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual(plan.score_plan.action, "reuse")
        self.assertEqual(plan.score_plan.reuse.created_at, first_time)
        self.assertEqual(plan.score_plan.reuse.updated_at, first_time)
        conn.execute(
            "UPDATE assessments SET company='substituted' WHERE profile_id=? AND job_key=?",
            (kwargs["profile_id"], kwargs["job_key"]),
        )
        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual(caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT)

    def test_plan_any_existing_processing_event_conflicts(self) -> None:
        conn, _, _ = self._make_two_db_connection()
        kwargs = self._plan_kwargs()
        for index in range(2):
            conn.execute(
                "INSERT INTO assessment_events(profile_id,job_key,event_type,actor_kind,"
                "payload_json,idempotency_key,created_at) VALUES(?,?,?,?,?,?,?)",
                (
                    kwargs["profile_id"],
                    kwargs["job_key"],
                    "processing_score_accepted",
                    "deterministic",
                    "{}",
                    f"existing-{index}",
                    kwargs["accepted_at"],
                ),
            )
        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module.plan_reason14_projections(conn, **kwargs)
        self.assertEqual(caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT)

    def test_plan_propagates_sqlite_storage_errors(self) -> None:
        class BrokenConnection:
            def execute(self, *args):
                del args
                raise sqlite3.OperationalError("injected storage failure")

        with self.assertRaises(sqlite3.OperationalError):
            processing_module.plan_reason14_projections(
                BrokenConnection(), **self._plan_kwargs()
            )

    def test_result_from_staged_roundtrip(self) -> None:
        expected = self._result()
        reconstructed = processing_module.result_from_staged(self._score_facts())
        self.assertEqual(reconstructed, expected)

    def test_result_rejects_every_identity_drift(self) -> None:
        base = dataclasses.asdict(self._result())
        mutations = {
            "profile_id": "prf_" + "b" * 32,
            "job_key": "boards.example:other",
            "track": "other",
            "fit_status": "other",
            "parameters_hash": "0" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                node = copy.deepcopy(base)
                node[field] = value
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.result_from_staged(self._score_facts(node))
                self.assertEqual(caught.exception.reason, processing_module.REASON_SCORE_RESULT)

    def test_result_rejects_numeric_types_values_and_subscore_keysets(self) -> None:
        base = dataclasses.asdict(self._result())
        mutations = []
        for field in ("fit", "opportunity", "final"):
            node = copy.deepcopy(base)
            node[field] = int(node[field])
            mutations.append(node)
        node = copy.deepcopy(base)
        node["fit_subscores"]["interest"] = 0
        mutations.append(node)
        node = copy.deepcopy(base)
        del node["fit_subscores"]["interest"]
        mutations.append(node)
        node = copy.deepcopy(base)
        node["opportunity_subscores"]["extra"] = 0.0
        mutations.append(node)
        for node in mutations:
            with self.subTest(node=node):
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.result_from_staged(self._score_facts(node))
                self.assertEqual(caught.exception.reason, processing_module.REASON_SCORE_RESULT)

    def test_result_rejects_malformed_utf8_json_and_noncanonical_bytes(self) -> None:
        base = dataclasses.asdict(self._result())
        variants = (
            b"\xff",
            b"{",
            json.dumps(base, ensure_ascii=False, sort_keys=True, indent=2).encode(),
            processing_module.canonical_json(
                {**base, "extra": "forbidden"}
            ).encode(),
        )
        for payload in variants:
            with self.subTest(payload=payload[:24]):
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.result_from_staged(
                        self._score_facts(raw_bytes=payload)
                    )
                self.assertEqual(caught.exception.reason, processing_module.REASON_SCORE_RESULT)

    def test_increment_has_no_provider_model_network_or_browser_import(self) -> None:
        source = inspect.getsource(processing_module.setup_transaction_sqlite)
        source += inspect.getsource(processing_module.plan_reason14_projections)
        source += inspect.getsource(processing_module.result_from_staged)
        for forbidden in (
            "LLMClient",
            "requests",
            "urllib",
            "playwright",
            "browser",
            "provider",
            "datetime.now",
            "time.time",
        ):
            self.assertNotIn(forbidden, source)


class StageDPart3C2Increment2Tests(unittest.TestCase):
    """C2 Increment 2: read-only event ID and immutable receipt planning."""

    ACCEPTED_AT = "2026-08-25T12:00:00Z"
    HISTORICAL_AT = "2026-08-20T10:00:00Z"

    class _Cursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

    class _ScriptedConnection:
        def __init__(self, outcomes):
            self.outcomes = list(outcomes)
            self.statements = []

        def execute(self, sql):
            self.statements.append(sql)
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, sqlite3.Error):
                raise outcome
            return StageDPart3C2Increment2Tests._Cursor(outcome)

    def _make_connection(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        main_path = os.path.join(tmp, "assessments.sqlite3")
        vacancy_path = os.path.join(tmp, "vacancies.sqlite3")
        owner = sqlite3.connect(main_path)
        owner.executescript(research_store_module.SCHEMA)
        owner.close()
        from market_aligner.state import vacancies as vacancies_module

        owner = sqlite3.connect(vacancy_path)
        owner.executescript(vacancies_module.SCHEMA)
        owner.close()
        connection = sqlite3.connect(main_path)
        connection.execute("ATTACH DATABASE ? AS vacancy", (vacancy_path,))
        self.addCleanup(connection.close)
        return connection

    def _facts(self, job_key="boards.example:j-1"):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        golden = StageDEnvelopeAuthorityTests(
            "test_golden_envelope_binds_linked_immutable_facts"
        )
        payload = golden._golden_payload(tmp)
        if job_key != payload["job_key"]:
            payload["job_key"] = job_key
            payload["alignment"]["output"]["job_key"] = job_key
            payload["alignment"]["receipt"]["output_sha256"] = hashlib.sha256(
                processing_module.canonical_json(
                    payload["alignment"]["output"]
                ).encode("utf-8")
            ).hexdigest()
            payload["scoring"]["expected_score"]["job_key"] = job_key
        raw = processing_module.canonical_json(payload).encode("utf-8") + b"\n"
        facts = processing_module.compose_envelope_facts(
            payload,
            envelope_file_sha256=hashlib.sha256(raw).hexdigest(),
            expected_assessments_path=str(
                tmp / "state" / "assessments.sqlite3"
            ),
            expected_vacancy_path=str(tmp / "state" / "vacancies.sqlite3"),
        )
        return facts, payload

    def _reason14(self, connection, facts, *, reuse=False):
        result = processing_module.result_from_staged(facts)
        normalized_json = processing_module.canonical_json(
            {"company": "Example", "title": "Engineer"}
        )
        normalized_hash = hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()
        if reuse:
            connection.execute(
                "INSERT INTO vacancy.normalised_jobs"
                "(key,normalized_json,normalized_at) VALUES(?,?,?)",
                (facts.job_key, normalized_json, self.HISTORICAL_AT),
            )
            research_store_module.cas_accepted_score(
                connection,
                result=result,
                url="https://example.test/job",
                title="Engineer",
                company="Example",
                extraction_confidence=0.9,
                accepted_at=self.HISTORICAL_AT,
            )
        return processing_module.plan_reason14_projections(
            connection,
            result_obj=result,
            url="https://example.test/job",
            title="Engineer",
            company="Example",
            extraction_confidence=0.9,
            job_key=facts.job_key,
            profile_id=facts.profile_id,
            normalized_json=normalized_json,
            normalized_json_sha256=normalized_hash,
            accepted_at=self.ACCEPTED_AT,
        )

    def _plan(self, *, reuse=False, job_key="boards.example:j-1"):
        connection = self._make_connection()
        facts, payload = self._facts(job_key)
        reason14 = self._reason14(connection, facts, reuse=reuse)
        event_id = processing_module._prospective_event_id(connection)
        plan = processing_module.build_prospective_plan(
            facts=facts,
            reason14=reason14,
            accepted_at=self.ACCEPTED_AT,
            prospective_event_id=event_id,
        )
        return plan, reason14, facts, payload, connection

    def test_prospective_id_uses_sequence_and_max_without_writes(self) -> None:
        connection = self._make_connection()
        statements = []
        connection.set_trace_callback(statements.append)
        self.assertEqual(processing_module._prospective_event_id(connection), 1)
        connection.set_trace_callback(None)
        connection.execute(
            "INSERT INTO assessment_events(profile_id,job_key,event_type,"
            "actor_kind,idempotency_key) "
            "VALUES('p','k','t','deterministic','one')"
        )
        connection.execute("DELETE FROM assessment_events")
        connection.execute(
            "UPDATE sqlite_sequence SET seq=9 WHERE name='assessment_events'"
        )
        self.assertEqual(processing_module._prospective_event_id(connection), 10)
        connection.execute(
            "INSERT INTO assessment_events(id,profile_id,job_key,event_type,"
            "actor_kind,idempotency_key) "
            "VALUES(15,'p','k','t','deterministic','fifteen')"
        )
        self.assertEqual(processing_module._prospective_event_id(connection), 16)
        self.assertTrue(statements)
        self.assertTrue(
            all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
        )

    def test_prospective_id_accepts_absent_sequence_catalogue(self) -> None:
        connection = self._ScriptedConnection(([], [(None,)]))
        self.assertEqual(processing_module._prospective_event_id(connection), 1)
        self.assertEqual(len(connection.statements), 2)

    def test_prospective_id_rejects_every_malformed_shape_and_overflow(self) -> None:
        cases = (
            ([["sqlite_sequence"]],),
            ([("sqlite_sequence",)], [(1,), (2,)]),
            ([("sqlite_sequence",)], [[1]], [(None,)]),
            ([("sqlite_sequence",)], [(True,)], [(None,)]),
            ([("sqlite_sequence",)], [(-1,)], [(None,)]),
            ([], []),
            ([], [[None]]),
            ([], [(None,), (None,)]),
            ([], [(True,)]),
            ([], [(-1,)]),
            ([], [(processing_module.MAX_EVENT_ID,)]),
        )
        for outcomes in cases:
            with self.subTest(outcomes=outcomes):
                connection = self._ScriptedConnection(outcomes)
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module._prospective_event_id(connection)
                self.assertEqual(
                    caught.exception.reason, processing_module.REASON_ATOMIC_MODE
                )

    def test_prospective_id_propagates_sqlite_errors(self) -> None:
        for outcomes in (
            (sqlite3.OperationalError("catalogue"),),
            ([("sqlite_sequence",)], sqlite3.DatabaseError("sequence")),
            ([], sqlite3.OperationalError("maximum")),
        ):
            with self.subTest(outcomes=outcomes):
                with self.assertRaises(sqlite3.Error):
                    processing_module._prospective_event_id(
                        self._ScriptedConnection(outcomes)
                    )

    def test_insert_plan_is_self_validating_frozen_and_false_authority(self) -> None:
        plan, reason14, facts, payload, _connection = self._plan()
        parsed, reconstructed = processing_module._self_validating_receipt(
            plan.sealed_bytes
        )
        self.assertEqual(reconstructed, facts)
        self.assertEqual(parsed["self_hash"], plan.receipt_self_hash)
        self.assertEqual(parsed["binding_sha256"], plan.binding_sha256)
        self.assertEqual(
            hashlib.sha256(plan.sealed_bytes).hexdigest(),
            plan.receipt_file_sha256,
        )
        self.assertEqual(parsed["created_at"], self.ACCEPTED_AT)
        self.assertEqual(parsed["assessment_event"]["created_at"], self.ACCEPTED_AT)
        self.assertEqual(parsed["assessment_projection"]["created_at"], self.ACCEPTED_AT)
        self.assertEqual(parsed["normalised_projection"]["normalized_at"], self.ACCEPTED_AT)
        self.assertEqual(
            parsed["assessment_event"]["idempotency_key"],
            processing_module.expected_idempotency_key(
                facts.profile_id,
                facts.job_key,
                parsed["assessment_event"]["payload_sha256"],
            ),
        )
        self.assertTrue(all(parsed[name] is False for name in processing_module._RECEIPT_FALSE_FLAGS))
        self.assertIs(reason14, plan.reason14)
        self.assertEqual(
            reason14.normalized_json_sha256,
            plan.reason14.normalized_json_sha256,
        )
        self.assertFalse(hasattr(plan, "receipt"))
        processing_module._assert_fully_immutable(plan, "prospective_plan")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.event_id = 2
        payload["track"] = "mutated-after-facts"
        self.assertEqual(
            processing_module.parse_processing_receipt(plan.sealed_bytes)["track"],
            facts.track,
        )

    def test_reuse_plan_preserves_historical_projection_timestamps(self) -> None:
        plan, _reason14, _facts, _payload, _connection = self._plan(reuse=True)
        parsed = processing_module.parse_processing_receipt(plan.sealed_bytes)
        self.assertEqual(parsed["created_at"], self.ACCEPTED_AT)
        self.assertEqual(parsed["assessment_event"]["created_at"], self.ACCEPTED_AT)
        self.assertEqual(
            parsed["normalised_projection"]["normalized_at"],
            self.HISTORICAL_AT,
        )
        self.assertEqual(
            parsed["assessment_projection"]["created_at"],
            self.HISTORICAL_AT,
        )
        self.assertEqual(
            parsed["assessment_projection"]["updated_at"],
            self.HISTORICAL_AT,
        )

    def test_unicode_job_key_binds_exact_utf8_without_normalization(self) -> None:
        composed = self._plan(job_key="boards.example:caf\N{LATIN SMALL LETTER E WITH ACUTE}")[0]
        decomposed = self._plan(job_key="boards.example:cafe\N{COMBINING ACUTE ACCENT}")[0]
        self.assertNotEqual(composed.idempotency_key, decomposed.idempotency_key)
        self.assertEqual(len(composed.idempotency_key.encode("ascii")), 183)
        self.assertEqual(len(decomposed.idempotency_key.encode("ascii")), 183)

    def test_plan_rejects_substituted_projection_and_event_authority(self) -> None:
        _plan, reason14, facts, _payload, _connection = self._plan()
        mutations = (
            dataclasses.replace(reason14, normalized_json="{}"),
            dataclasses.replace(reason14, normalized_json_sha256="0" * 64),
            dataclasses.replace(reason14, score_payload_hash="0" * 64),
            dataclasses.replace(reason14, event_action="reuse"),
            dataclasses.replace(reason14, normalized_at=self.HISTORICAL_AT),
            dataclasses.replace(
                reason14,
                score_plan=dataclasses.replace(
                    reason14.score_plan,
                    insert=dataclasses.replace(
                        reason14.score_plan.insert,
                        profile_id="prf_" + "b" * 32,
                    ),
                ),
            ),
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.build_prospective_plan(
                        facts=facts,
                        reason14=mutated,
                        accepted_at=self.ACCEPTED_AT,
                        prospective_event_id=1,
                    )
                self.assertEqual(
                    caught.exception.reason,
                    processing_module.REASON_PROJECTION_CONFLICT,
                )
        for event_id in (True, 0, -1, processing_module.MAX_EVENT_ID + 1):
            with self.subTest(event_id=event_id):
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.build_prospective_plan(
                        facts=facts,
                        reason14=reason14,
                        accepted_at=self.ACCEPTED_AT,
                        prospective_event_id=event_id,
                    )
                self.assertEqual(
                    caught.exception.reason, processing_module.REASON_ATOMIC_MODE
                )

    def test_receipt_size_boundary_is_inclusive_and_exact(self) -> None:
        maximum = b"x" * processing_module.MAX_RECEIPT_BYTES
        self.assertIs(processing_module._enforce_receipt_size(maximum), maximum)
        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module._enforce_receipt_size(maximum + b"x")
        self.assertEqual(
            caught.exception.reason, processing_module.REASON_ENVELOPE_BYTES
        )

    def test_increment_is_pure_and_contains_no_runtime_authority(self) -> None:
        source = inspect.getsource(processing_module._prospective_event_id)
        source += inspect.getsource(processing_module.build_prospective_plan)
        for forbidden in (
            "connection.commit(",
            "connection.rollback(",
            'connection.execute("INSERT',
            'connection.execute("UPDATE',
            'connection.execute("DELETE',
            "datetime.now",
            "time.time",
            "LLMClient",
            "requests",
            "playwright",
            "browser",
        ):
            self.assertNotIn(forbidden, source)


class StageDPart3C2Increment3Tests(unittest.TestCase):
    """C2 Increment 3: exact DDL/DML body under a caller transaction."""

    ACCEPTED_AT = "2026-08-25T12:00:00Z"
    HISTORICAL_AT = "2026-08-20T10:00:00Z"

    def _connection(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        main_path = os.path.join(tmp, "assessments.sqlite3")
        vacancy_path = os.path.join(tmp, "vacancies.sqlite3")
        owner = sqlite3.connect(main_path)
        owner.executescript(research_store_module.SCHEMA)
        owner.close()
        from market_aligner.state import vacancies as vacancies_module

        owner = sqlite3.connect(vacancy_path)
        owner.executescript(vacancies_module.SCHEMA)
        owner.close()
        connection = sqlite3.connect(main_path)
        connection.execute("ATTACH DATABASE ? AS vacancy", (vacancy_path,))
        self.addCleanup(connection.close)
        processing_module.setup_transaction_sqlite(connection)
        return connection

    def _facts(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        golden = StageDEnvelopeAuthorityTests(
            "test_golden_envelope_binds_linked_immutable_facts"
        )
        payload = golden._golden_payload(tmp)
        raw = processing_module.canonical_json(payload).encode("utf-8") + b"\n"
        return processing_module.compose_envelope_facts(
            payload,
            envelope_file_sha256=hashlib.sha256(raw).hexdigest(),
            expected_assessments_path=str(
                tmp / "state" / "assessments.sqlite3"
            ),
            expected_vacancy_path=str(tmp / "state" / "vacancies.sqlite3"),
        )

    def _seed_reusable(self, connection, facts):
        result = processing_module.result_from_staged(facts)
        normalized = processing_module.canonical_json(
            {"company": "Example", "title": "Engineer"}
        )
        connection.execute(
            "INSERT INTO vacancy.normalised_jobs"
            "(key,normalized_json,normalized_at) VALUES(?,?,?)",
            (facts.job_key, normalized, self.HISTORICAL_AT),
        )
        research_store_module.cas_accepted_score(
            connection,
            result=result,
            url="https://example.test/job",
            title="Engineer",
            company="Example",
            extraction_confidence=0.9,
            accepted_at=self.HISTORICAL_AT,
        )
        connection.commit()

    def _prepare(self, *, reuse=False):
        connection = self._connection()
        facts = self._facts()
        if reuse:
            self._seed_reusable(connection, facts)
        connection.execute("BEGIN IMMEDIATE")
        result = processing_module.result_from_staged(facts)
        normalized = processing_module.canonical_json(
            {"company": "Example", "title": "Engineer"}
        )
        reason14 = processing_module.plan_reason14_projections(
            connection,
            result_obj=result,
            url="https://example.test/job",
            title="Engineer",
            company="Example",
            extraction_confidence=0.9,
            job_key=facts.job_key,
            profile_id=facts.profile_id,
            normalized_json=normalized,
            normalized_json_sha256=hashlib.sha256(
                normalized.encode("utf-8")
            ).hexdigest(),
            accepted_at=self.ACCEPTED_AT,
        )
        plan = processing_module.build_prospective_plan(
            facts=facts,
            reason14=reason14,
            accepted_at=self.ACCEPTED_AT,
            prospective_event_id=processing_module._prospective_event_id(
                connection
            ),
        )
        return connection, plan

    def _domain_counts(self, connection):
        def count(alias, table):
            row = connection.execute(
                f"SELECT COUNT(*) FROM {alias}.{table}"
            ).fetchone()
            return row[0]

        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM main.sqlite_master WHERE type='table'"
            ).fetchall()
        }
        return {
            "normalized": count("vacancy", "normalised_jobs"),
            "assessment": count("main", "assessments"),
            "event": count("main", "assessment_events"),
            "receipt": (
                count("main", "processing_receipts")
                if "processing_receipts" in tables
                else 0
            ),
            "ledger": (
                count("main", "market_aligner_schema_migrations")
                if "market_aligner_schema_migrations" in tables
                else 0
            ),
            "has_receipt_table": "processing_receipts" in tables,
            "has_ledger": "market_aligner_schema_migrations" in tables,
        }

    def test_insert_applies_receipt_last_and_returns_immutable_exact_bytes(self):
        connection, plan = self._prepare()
        statements = []
        connection.set_trace_callback(statements.append)
        outcome = processing_module.apply_transaction_plan(connection, plan)
        connection.set_trace_callback(None)
        self.assertEqual(outcome.sealed_bytes, plan.sealed_bytes)
        self.assertEqual(outcome.event_id, plan.event_id)
        self.assertEqual(outcome.normalized_action, "insert")
        self.assertEqual(outcome.score_action, "insert")
        processing_module._assert_fully_immutable(outcome, "outcome")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.event_id = 2
        dml = [
            statement.strip().upper()
            for statement in statements
            if statement.lstrip().upper().startswith(
                ("INSERT", "UPDATE", "DELETE")
            )
        ]
        self.assertTrue(dml[-1].startswith("INSERT INTO MAIN.PROCESSING_RECEIPTS"))
        self.assertFalse(any(statement.startswith("UPDATE") for statement in dml))
        self.assertEqual(
            self._domain_counts(connection),
            {
                "normalized": 1,
                "assessment": 1,
                "event": 1,
                "receipt": 1,
                "ledger": 1,
                "has_receipt_table": True,
                "has_ledger": True,
            },
        )
        connection.commit()

    def test_reuse_keeps_historical_projection_timestamps(self):
        connection, plan = self._prepare(reuse=True)
        outcome = processing_module.apply_transaction_plan(connection, plan)
        self.assertEqual(outcome.normalized_action, "reuse")
        self.assertEqual(outcome.score_action, "reuse")
        receipt = processing_module.parse_processing_receipt(outcome.sealed_bytes)
        self.assertEqual(
            receipt["normalised_projection"]["normalized_at"],
            self.HISTORICAL_AT,
        )
        self.assertEqual(
            receipt["assessment_projection"]["created_at"],
            self.HISTORICAL_AT,
        )
        self.assertEqual(
            receipt["assessment_projection"]["updated_at"],
            self.HISTORICAL_AT,
        )
        self.assertEqual(self._domain_counts(connection)["assessment"], 1)
        connection.commit()

    def test_every_logical_fault_rolls_back_both_databases_then_retries(self):
        boundaries = (
            "after_migration_apply",
            "after_normalized_cas",
            "after_assessment_cas",
            "after_event_insert",
            "after_receipt_insert",
            "after_transaction_reread",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                connection, plan = self._prepare()
                processing_module.install_fault(boundary, RuntimeError(boundary))
                try:
                    with self.assertRaisesRegex(RuntimeError, boundary):
                        processing_module.apply_transaction_plan(connection, plan)
                finally:
                    processing_module.clear_faults()
                    connection.rollback()
                self.assertEqual(
                    self._domain_counts(connection),
                    {
                        "normalized": 0,
                        "assessment": 0,
                        "event": 0,
                        "receipt": 0,
                        "ledger": 0,
                        "has_receipt_table": False,
                        "has_ledger": False,
                    },
                )
                connection.execute("BEGIN IMMEDIATE")
                outcome = processing_module.apply_transaction_plan(connection, plan)
                self.assertEqual(outcome.sealed_bytes, plan.sealed_bytes)
                connection.commit()

    def test_fault_immediately_after_each_migration_ddl_rolls_back_schema(self):
        class Wrapper:
            def __init__(self, inner, needle):
                self.inner = inner
                self.needle = needle
                self.fired = False

            @property
            def in_transaction(self):
                return self.inner.in_transaction

            def execute(self, sql, *args):
                cursor = self.inner.execute(sql, *args)
                if not self.fired and self.needle in " ".join(sql.split()):
                    self.fired = True
                    raise RuntimeError(self.needle)
                return cursor

        needles = (
            "CREATE TABLE IF NOT EXISTS main.market_aligner_schema_migrations",
            "CREATE TABLE main.processing_receipts",
        )
        for needle in needles:
            with self.subTest(needle=needle):
                connection, plan = self._prepare()
                wrapper = Wrapper(connection, needle)
                with self.assertRaisesRegex(RuntimeError, "CREATE TABLE"):
                    processing_module.apply_transaction_plan(wrapper, plan)
                self.assertTrue(wrapper.fired)
                connection.rollback()
                counts = self._domain_counts(connection)
                self.assertFalse(counts["has_ledger"])
                self.assertFalse(counts["has_receipt_table"])

    def test_canonical_owner_action_and_event_identity_mismatch_refuse(self):
        import types
        import unittest.mock as mock

        connection, plan = self._prepare()
        with mock.patch.object(
            processing_module, "cas_normalized_job", return_value="reused"
        ):
            with self.assertRaises(processing_module.ProcessingRefused) as caught:
                processing_module.apply_transaction_plan(connection, plan)
        self.assertEqual(
            caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT
        )
        connection.rollback()

        connection, plan = self._prepare()
        fake_projection = types.SimpleNamespace(
            event_id=plan.event_id + 1,
            profile_id=plan.facts.profile_id,
            job_key=plan.facts.job_key,
            payload_json=plan.event_payload_json,
            idempotency_key=plan.idempotency_key,
            created_at=plan.accepted_at,
        )
        fake_outcome = types.SimpleNamespace(
            action="insert", projection=fake_projection
        )
        with mock.patch.object(
            processing_module,
            "cas_processing_event",
            return_value=fake_outcome,
        ):
            with self.assertRaises(processing_module.ProcessingRefused) as caught:
                processing_module.apply_transaction_plan(connection, plan)
        self.assertEqual(
            caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT
        )
        connection.rollback()

    def test_receipt_integrity_and_final_reread_substitution_refuse(self):
        import unittest.mock as mock

        connection, plan = self._prepare()
        real_execute = connection.execute

        class IntegrityConnection:
            @property
            def in_transaction(self):
                return connection.in_transaction

            def execute(self, sql, *args):
                if sql.lstrip().upper().startswith(
                    "INSERT INTO MAIN.PROCESSING_RECEIPTS"
                ):
                    raise sqlite3.IntegrityError("injected collision")
                return real_execute(sql, *args)

        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module.apply_transaction_plan(IntegrityConnection(), plan)
        self.assertEqual(
            caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT
        )
        connection.rollback()

        connection, plan = self._prepare()
        with mock.patch.object(
            processing_module,
            "read_normalized_job",
            return_value=("substituted", plan.reason14.normalized_at),
        ):
            with self.assertRaises(processing_module.ProcessingRefused) as caught:
                processing_module.apply_transaction_plan(connection, plan)
        self.assertEqual(
            caught.exception.reason, processing_module.REASON_PROJECTION_CONFLICT
        )
        connection.rollback()

    def test_migration_compatibility_maps_but_storage_errors_propagate(self):
        import unittest.mock as mock

        connection, plan = self._prepare()
        with mock.patch.object(
            processing_module,
            "apply_on",
            side_effect=processing_module.MigrationCompatibilityError("bad"),
        ):
            with self.assertRaises(processing_module.ProcessingRefused) as caught:
                processing_module.apply_transaction_plan(connection, plan)
        self.assertEqual(caught.exception.reason, processing_module.REASON_ATOMIC_MODE)
        connection.rollback()

        connection, plan = self._prepare()
        with mock.patch.object(
            processing_module,
            "apply_on",
            side_effect=sqlite3.OperationalError("storage"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                processing_module.apply_transaction_plan(connection, plan)
        connection.rollback()

    def test_recovery_classifier_proves_empty_then_complete_for_insert_and_reuse(self):
        for reuse in (False, True):
            with self.subTest(reuse=reuse):
                connection, plan = self._prepare(reuse=reuse)
                connection.rollback()
                empty = processing_module.classify_recovered_transaction(
                    connection, plan
                )
                self.assertEqual(
                    empty.disposition,
                    processing_module.RECOVERY_DURABLE_EMPTY,
                )
                self.assertIsNone(empty.stored_receipt_bytes)

                connection.execute("BEGIN IMMEDIATE")
                processing_module.apply_transaction_plan(connection, plan)
                connection.commit()
                complete = processing_module.classify_recovered_transaction(
                    connection, plan
                )
                self.assertEqual(
                    complete.disposition,
                    processing_module.RECOVERY_DURABLE_COMPLETE,
                )
                self.assertEqual(complete.stored_receipt_bytes, plan.sealed_bytes)
                processing_module._assert_fully_immutable(
                    complete, "recovered_transaction"
                )

    def test_recovery_classifier_rejects_every_partial_or_substituted_graph(self):
        mutations = (
            "receipt_removed",
            "normalized_removed",
            "normalized_substituted",
            "assessment_removed",
            "assessment_substituted",
            "event_removed",
            "extra_event",
            "receipt_bytes_substituted",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                connection, plan = self._prepare()
                processing_module.apply_transaction_plan(connection, plan)
                connection.commit()
                if mutation == "receipt_removed":
                    connection.execute(
                        "DELETE FROM main.processing_receipts WHERE operation_id=?",
                        (plan.facts.operation_id,),
                    )
                elif mutation == "normalized_removed":
                    connection.execute(
                        "DELETE FROM vacancy.normalised_jobs WHERE key=?",
                        (plan.facts.job_key,),
                    )
                elif mutation == "normalized_substituted":
                    connection.execute(
                        "UPDATE vacancy.normalised_jobs SET normalized_json='{}' "
                        "WHERE key=?",
                        (plan.facts.job_key,),
                    )
                elif mutation == "assessment_removed":
                    connection.execute(
                        "PRAGMA foreign_keys=OFF"
                    )
                    connection.execute(
                        "DELETE FROM main.assessments "
                        "WHERE profile_id=? AND job_key=?",
                        (plan.facts.profile_id, plan.facts.job_key),
                    )
                elif mutation == "assessment_substituted":
                    connection.execute(
                        "UPDATE main.assessments SET title='substituted' "
                        "WHERE profile_id=? AND job_key=?",
                        (plan.facts.profile_id, plan.facts.job_key),
                    )
                elif mutation == "event_removed":
                    connection.execute("PRAGMA foreign_keys=OFF")
                    connection.execute(
                        "DELETE FROM main.assessment_events WHERE id=?",
                        (plan.event_id,),
                    )
                elif mutation == "extra_event":
                    connection.execute(
                        "INSERT INTO main.assessment_events("
                        "profile_id,job_key,event_type,actor_kind,payload_json,"
                        "idempotency_key,created_at) VALUES(?,?,?,?,?,?,?)",
                        (
                            plan.facts.profile_id,
                            plan.facts.job_key,
                            processing_module.EVENT_TYPE_PROCESSING_SCORE_ACCEPTED,
                            "deterministic",
                            plan.event_payload_json,
                            "different-idempotency-key",
                            plan.accepted_at,
                        ),
                    )
                elif mutation == "receipt_bytes_substituted":
                    connection.execute(
                        "UPDATE main.processing_receipts SET receipt_bytes=? "
                        "WHERE operation_id=?",
                        (b"{}\n", plan.facts.operation_id),
                    )
                connection.commit()
                recovered = processing_module.classify_recovered_transaction(
                    connection, plan
                )
                self.assertEqual(
                    recovered.disposition,
                    processing_module.RECOVERY_DURABLE_INCOHERENT,
                )
                self.assertIsNone(recovered.stored_receipt_bytes)

    def test_recovery_classifier_rejects_migration_and_event_id_ambiguity(self):
        connection, plan = self._prepare()
        connection.rollback()
        connection.execute(processing_module.LEDGER_DDL)
        connection.commit()
        recovered = processing_module.classify_recovered_transaction(
            connection, plan
        )
        self.assertEqual(
            recovered.disposition,
            processing_module.RECOVERY_DURABLE_INCOHERENT,
        )

        connection, plan = self._prepare()
        connection.rollback()
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO main.assessment_events("
            "id,profile_id,job_key,event_type,actor_kind,payload_json,"
            "idempotency_key,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                plan.event_id,
                "prf_" + "f" * 32,
                "boards.example:unrelated",
                "processing_score_accepted",
                "deterministic",
                "{}",
                "unrelated-event-id",
                self.ACCEPTED_AT,
            ),
        )
        connection.commit()
        recovered = processing_module.classify_recovered_transaction(
            connection, plan
        )
        self.assertEqual(
            recovered.disposition,
            processing_module.RECOVERY_DURABLE_INCOHERENT,
        )

        class Rows:
            def fetchall(self):
                return [("malformed",)]

        class MalformedIndexConnection:
            def execute(self, sql, *args):
                if sql == "PRAGMA index_list(processing_receipts)":
                    return Rows()
                return connection.execute(sql, *args)

        connection, plan = self._prepare()
        processing_module.apply_transaction_plan(connection, plan)
        connection.commit()
        recovered = processing_module.classify_recovered_transaction(
            MalformedIndexConnection(), plan
        )
        self.assertEqual(
            recovered.disposition,
            processing_module.RECOVERY_DURABLE_INCOHERENT,
        )

    def test_recovery_classifier_is_read_only_and_has_no_runtime_owner(self):
        connection, plan = self._prepare()
        connection.rollback()
        statements = []
        connection.set_trace_callback(statements.append)
        recovered = processing_module.classify_recovered_transaction(
            connection, plan
        )
        connection.set_trace_callback(None)
        self.assertEqual(
            recovered.disposition,
            processing_module.RECOVERY_DURABLE_EMPTY,
        )
        self.assertTrue(statements)
        self.assertTrue(
            all(
                statement.lstrip().upper().startswith(("SELECT", "PRAGMA"))
                for statement in statements
            ),
            statements,
        )
        source = inspect.getsource(
            processing_module.classify_recovered_transaction
        )
        for forbidden in (
            "sqlite3.connect",
            "ATTACH DATABASE",
            "BEGIN",
            ".commit(",
            ".rollback(",
            "journal_mode",
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "apply_on(",
            "cas_accepted_score(",
            "cas_processing_event(",
        ):
            self.assertNotIn(forbidden, source)

    def test_recovered_connection_verifies_both_databases_around_classification(self):
        connection, plan = self._prepare()
        statements = []
        connection.set_trace_callback(statements.append)
        empty = processing_module.verify_recovered_connection(connection, plan)
        connection.set_trace_callback(None)
        self.assertEqual(
            empty.disposition,
            processing_module.RECOVERY_DURABLE_EMPTY,
        )
        self.assertTrue(
            all(
                statement.lstrip().upper().startswith(("SELECT", "PRAGMA"))
                for statement in statements
            ),
            statements,
        )

        processing_module.apply_transaction_plan(connection, plan)
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        complete = processing_module.verify_recovered_connection(connection, plan)
        self.assertEqual(
            complete.disposition,
            processing_module.RECOVERY_DURABLE_COMPLETE,
        )
        self.assertEqual(complete.stored_receipt_bytes, plan.sealed_bytes)
        connection.rollback()

    def test_recovered_connection_rejects_integrity_alias_and_shape_failures(self):
        connection, plan = self._prepare()

        class Rows:
            def __init__(self, values):
                self.values = values

            def fetchall(self):
                return self.values

        class Wrapped:
            def __init__(self, override):
                self.override = override

            @property
            def in_transaction(self):
                return connection.in_transaction

            def execute(self, sql, *args):
                if sql in self.override:
                    value = self.override[sql]
                    if isinstance(value, BaseException):
                        raise value
                    return Rows(value)
                return connection.execute(sql, *args)

        cases = (
            {"PRAGMA database_list": [(0, "main", "/same"), (2, "vacancy", "/same")]},
            {"PRAGMA main.quick_check": [("not ok",)]},
            {"PRAGMA vacancy.quick_check": [["ok"]]},
            {"PRAGMA main.foreign_key_check": [("assessments", 1, "parent", 0)]},
        )
        for override in cases:
            with self.subTest(override=override):
                with self.assertRaises(processing_module.ProcessingRefused) as caught:
                    processing_module.verify_recovered_connection(
                        Wrapped(override), plan
                    )
                self.assertEqual(
                    caught.exception.reason,
                    processing_module.REASON_RECOVERY_INCOHERENT,
                )

        injected = sqlite3.OperationalError("busy")
        with self.assertRaises(sqlite3.OperationalError):
            processing_module.verify_recovered_connection(
                Wrapped({"PRAGMA main.quick_check": injected}), plan
            )
        connection.rollback()

    def test_recovered_connection_requires_active_transaction_and_has_no_owner(self):
        connection, plan = self._prepare()
        connection.rollback()
        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module.verify_recovered_connection(connection, plan)
        self.assertEqual(
            caught.exception.reason,
            processing_module.REASON_RECOVERY_INCOHERENT,
        )
        source = inspect.getsource(processing_module.verify_recovered_connection)
        for forbidden in (
            "sqlite3.connect",
            "ATTACH DATABASE",
            "BEGIN IMMEDIATE",
            ".commit(",
            ".rollback(",
            "journal_mode",
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "apply_on(",
            "cas_accepted_score(",
            "cas_processing_event(",
        ):
            self.assertNotIn(forbidden, source)

    def test_helper_requires_active_transaction_and_has_no_runtime_owner(self):
        connection, plan = self._prepare()
        connection.rollback()
        with self.assertRaises(processing_module.ProcessingRefused) as caught:
            processing_module.apply_transaction_plan(connection, plan)
        self.assertEqual(caught.exception.reason, processing_module.REASON_ATOMIC_MODE)
        source = inspect.getsource(processing_module.apply_transaction_plan)
        for forbidden in (
            "sqlite3.connect",
            "ATTACH DATABASE",
            "BEGIN IMMEDIATE",
            ".commit(",
            ".rollback(",
            "datetime.now",
            "time.time",
            "LLMClient",
            "requests",
            "playwright",
            "browser",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
