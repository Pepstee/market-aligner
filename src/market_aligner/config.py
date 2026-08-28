"""Filesystem boundaries for product code and operator-owned data."""

from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


DATA_HOME_ENV = "MARKET_ALIGNER_DATA_HOME"
_OWNER_PRIVATE_LOCK = threading.RLock()


@contextmanager
def owner_private_umask() -> Iterator[None]:
    """Serialize cooperating creators while applying an owner-private umask."""

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
