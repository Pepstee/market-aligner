"""Disposable-repository helpers for JAA certification tests.

JAA is a Market Aligner subsystem, so an independent test checkout must clone
the enclosing Market Aligner repository and then return its JAA directory.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def clone_jaa_repository(jaa_root: Path, destination: Path) -> Path:
    """Clone canonical Market Aligner and return JAA inside the clone."""
    resolved_jaa = jaa_root.resolve()
    discovered = subprocess.run(
        ("git", "-C", str(resolved_jaa), "rev-parse", "--show-toplevel"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if discovered.returncode != 0:
        raise RuntimeError(
            f"cannot resolve the enclosing Market Aligner repository: {discovered.stderr.strip()}"
        )

    market_aligner_root = Path(discovered.stdout.strip()).resolve()
    try:
        relative_jaa = resolved_jaa.relative_to(market_aligner_root)
    except ValueError as error:
        raise RuntimeError(
            "JAA is not inside the resolved Market Aligner repository"
        ) from error
    if relative_jaa == Path("."):
        raise RuntimeError("JAA must be a subsystem, not a standalone repository")

    # Each disposable clone owns its refs, index, worktree, and newly written
    # objects.  The read-only alternate avoids copying Market Aligner's full
    # archaeological history into every adversarial fixture.
    cloned = subprocess.run(
        (
            "git",
            "clone",
            "--shared",
            str(market_aligner_root),
            str(destination),
        ),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cloned.returncode != 0:
        raise RuntimeError(f"cannot clone Market Aligner: {cloned.stderr.strip()}")

    cloned_jaa = destination / relative_jaa
    if not cloned_jaa.is_dir():
        raise RuntimeError(
            f"cloned Market Aligner is missing its JAA subsystem: {relative_jaa}"
        )
    return cloned_jaa
