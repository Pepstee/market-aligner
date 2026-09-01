"""FIT-001 Stage A: owner-private mode/umask foundations."""

from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from market_aligner.config import (
    create_private_database_file,
    ensure_private_directory,
    owner_private_umask,
)


def _probe_umask() -> int:
    """Read the current umask without leaving it changed."""
    prior = os.umask(0o077)
    os.umask(prior)
    return prior


class OwnerPrivateUmaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_umask = _probe_umask()
        self.addCleanup(os.umask, self._saved_umask)

    def test_nested_scopes_apply_and_restore(self) -> None:
        with owner_private_umask():
            self.assertEqual(0o077, _probe_umask())
            with owner_private_umask():
                self.assertEqual(0o077, _probe_umask())
            self.assertEqual(0o077, _probe_umask())
        self.assertEqual(self._saved_umask, _probe_umask())

    def test_exception_inside_scope_still_restores(self) -> None:
        with self.assertRaises(RuntimeError):
            with owner_private_umask():
                self.assertEqual(0o077, _probe_umask())
                raise RuntimeError("boom")
        self.assertEqual(self._saved_umask, _probe_umask())

    def test_cooperating_threads_serialize_and_restore(self) -> None:
        observed: list[int] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(2)

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                with owner_private_umask():
                    observed.append(_probe_umask())
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual([], errors)
        # Each cooperating scope observed the restrictive umask while held.
        self.assertEqual([0o077, 0o077], sorted(observed))
        self.assertEqual(self._saved_umask, _probe_umask())

    def test_dedicated_process_limitation_is_documented(self) -> None:
        # The lock serializes cooperating callers only; this suite states the
        # documented compatibility limitation rather than denying it.
        import inspect

        from market_aligner import config

        source = inspect.getsource(config.owner_private_umask)
        self.assertIn("cooperating", source)
        self.assertIn("noncooperating", inspect.getsource(config))


class EnsurePrivateDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        # Canonical (symlink-resolved) authority root, as ProductPaths.resolve
        # provides at the trusted caller boundary.
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_creates_missing_directory_at_0700(self) -> None:
        target = self.root / "state" / "profiles"
        ensure_private_directory(target)
        info = os.lstat(target)
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual(0o700, stat.S_IMODE(info.st_mode))

    def test_accepts_existing_0700_even_when_nlink_exceeds_one(self) -> None:
        target = self.root / "profiles"
        target.mkdir(mode=0o700)
        (target / "child").mkdir()
        # A subdirectory raises the parent's link count on most filesystems;
        # directory nlink is platform dependent and must NOT be asserted.
        ensure_private_directory(target)

    def test_refuses_wrong_mode_without_chmod(self) -> None:
        target = self.root / "loose"
        target.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            ensure_private_directory(target)
        self.assertEqual(0o755, stat.S_IMODE(os.lstat(target).st_mode))

    def test_refuses_symlink(self) -> None:
        real = self.root / "real"
        real.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(real)
        with self.assertRaises(ValueError):
            ensure_private_directory(link)

    def test_refuses_regular_file(self) -> None:
        target = self.root / "file"
        target.write_text("x", encoding="utf-8")
        with self.assertRaises(ValueError):
            ensure_private_directory(target)

    def test_refuses_0700_target_symlink_ancestor(self) -> None:
        target = self.root / "elsewhere"
        target.mkdir(mode=0o700)
        link = self.root / "state"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            ensure_private_directory(link / "child", authority_root=self.root)
        # The attacker-chosen target stays empty; the symlink itself may remain.
        self.assertEqual([], list(target.iterdir()))

    def test_direct_parent_substitution_refused(self) -> None:
        real = self.root / "realparent"
        real.mkdir(mode=0o700)
        decoy = self.root / "decoy"
        decoy.mkdir(mode=0o700)
        swapped = self.root / "swap"
        swapped.symlink_to(decoy)
        with self.assertRaises(ValueError):
            ensure_private_directory(swapped, authority_root=self.root)


class CreatePrivateDatabaseFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_creates_parents_and_file_with_exact_modes(self) -> None:
        database = self.root / "state" / "vacancies.sqlite3"
        create_private_database_file(database, authority_root=self.root)
        self.assertEqual(
            0o700,
            stat.S_IMODE(os.lstat(database.parent).st_mode),
        )
        info = os.lstat(database)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        self.assertEqual(1, info.st_nlink)

    def test_existing_correct_file_is_accepted_unchanged(self) -> None:
        database = self.root / "db.sqlite3"
        create_private_database_file(database, authority_root=self.root)
        before = os.lstat(database)
        create_private_database_file(database, authority_root=self.root)
        self.assertEqual(before.st_ino, os.lstat(database).st_ino)
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(database).st_mode))

    def test_existing_wrong_mode_refuses_without_chmod(self) -> None:
        database = self.root / "loose.sqlite3"
        descriptor = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(descriptor)
        with self.assertRaises(ValueError):
            create_private_database_file(database, authority_root=self.root)
        self.assertEqual(0o644, stat.S_IMODE(os.lstat(database).st_mode))

    def test_symlink_leaf_refuses(self) -> None:
        real = self.root / "real.sqlite3"
        create_private_database_file(real, authority_root=self.root)
        link = self.root / "link.sqlite3"
        link.symlink_to(real)
        with self.assertRaises(ValueError):
            create_private_database_file(link, authority_root=self.root)

    def test_refuses_0700_target_symlink_ancestor_without_creating_leaf(self) -> None:
        target = self.root / "elsewhere"
        target.mkdir(mode=0o700)
        link = self.root / "state"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            create_private_database_file(
                link / "child.sqlite3", authority_root=self.root
            )
        self.assertEqual([], list(target.iterdir()))

    def test_existing_loose_parent_refuses_without_chmod(self) -> None:
        parent = self.root / "looseparent"
        parent.mkdir(mode=0o755)
        database = parent / "db.sqlite3"
        with self.assertRaises(ValueError):
            create_private_database_file(database, authority_root=self.root)
        self.assertEqual(0o755, stat.S_IMODE(os.lstat(parent).st_mode))


if __name__ == "__main__":
    unittest.main()
