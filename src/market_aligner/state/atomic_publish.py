"""Portable atomic no-replace publication for private receipt files."""

from __future__ import annotations

import ctypes
import errno
import os


def publish_noreplace(
    directory_descriptor: int,
    temporary_name: str,
    final_name: str,
) -> bool:
    """Atomically publish ``temporary_name`` unless ``final_name`` exists.

    Linux exposes ``renameat2(RENAME_NOREPLACE)`` while Darwin exposes the
    equivalent ``renameatx_np(RENAME_EXCL)``.  The hard-link fallback retains
    create-or-exact semantics on other POSIX systems; the caller's cleanup
    removes its private staging name.
    """

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
        flag = 1  # RENAME_NOREPLACE
    except AttributeError:
        try:
            rename = libc.renameatx_np
            flag = 0x00000004  # RENAME_EXCL
        except AttributeError:
            try:
                os.link(
                    temporary_name,
                    final_name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                return False
            return True

    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if (
        rename(
            directory_descriptor,
            os.fsencode(temporary_name),
            directory_descriptor,
            os.fsencode(final_name),
            flag,
        )
        == 0
    ):
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    raise OSError(error, os.strerror(error))
