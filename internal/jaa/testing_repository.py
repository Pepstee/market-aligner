"""Disposable-repository helpers for JAA certification tests.

JAA is a Market Aligner subsystem, so an independent test checkout must clone
the enclosing Market Aligner repository and then return its JAA directory.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import FunctionType, ModuleType
from typing import IO, Any, Iterator


HISTORICAL_OPERATOR_CONTROL_ROOT = Path("/home/gutua/software-factory/.control")
HISTORICAL_SOFTWARE_FACTORY_ROOT = Path("/home/gutua/software-factory")
HISTORICAL_NATIVE_JAA_ROOT = HISTORICAL_SOFTWARE_FACTORY_ROOT / (
    ".worktrees/jaa-native-completion"
)
HISTORICAL_OPERATIONAL_STATE_ROOT = HISTORICAL_SOFTWARE_FACTORY_ROOT / (
    ".incoming/mac-jaa-assurance-20260805-e1bb35a/operational-state"
)
LOCAL_OPERATIONAL_STATE_MARKER = Path(
    "job-application-automation-gutua-20260803-evidence"
)


class _HistoricalMappedPath(type(Path())):
    """A lexical historical path whose filesystem operations use a local mirror."""

    _prefixes: tuple[tuple[Path, Path], ...] = ()

    def _actual(self) -> Path:
        lexical = Path(str(self))
        for historical, local in self._prefixes:
            try:
                relative = lexical.relative_to(historical)
            except ValueError:
                continue
            return local / relative
        return lexical

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        return self._actual().exists(follow_symlinks=follow_symlinks)

    def is_file(self) -> bool:
        return self._actual().is_file()

    def is_dir(self) -> bool:
        return self._actual().is_dir()

    def is_symlink(self) -> bool:
        return self._actual().is_symlink()

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        return self._actual().stat(follow_symlinks=follow_symlinks)

    def lstat(self) -> os.stat_result:
        return self._actual().lstat()

    def open(
        self,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> IO[Any]:
        return self._actual().open(mode, buffering, encoding, errors, newline)

    def read_bytes(self) -> bytes:
        return self._actual().read_bytes()

    def read_text(
        self,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        return self._actual().read_text(encoding=encoding, errors=errors)

    def resolve(self, strict: bool = False) -> _HistoricalMappedPath:
        if any(
            Path(str(self)).is_relative_to(historical)
            for historical, _local in self._prefixes
        ):
            if strict and not self.exists():
                raise FileNotFoundError(str(self))
            return self
        return type(self)(str(self._actual().resolve(strict=strict)))

    def iterdir(self) -> Iterator[_HistoricalMappedPath]:
        for child in self._actual().iterdir():
            yield self / child.name

    def glob(
        self,
        pattern: str,
        *,
        case_sensitive: bool | None = None,
    ) -> Iterator[_HistoricalMappedPath]:
        for child in self._actual().glob(
            pattern,
            case_sensitive=case_sensitive,
        ):
            yield self / child.relative_to(self._actual())

    def rglob(
        self,
        pattern: str,
        *,
        case_sensitive: bool | None = None,
    ) -> Iterator[_HistoricalMappedPath]:
        for child in self._actual().rglob(
            pattern,
            case_sensitive=case_sensitive,
        ):
            yield self / child.relative_to(self._actual())


def _map_historical_value(value: Any) -> Any:
    if isinstance(value, Path):
        return _HistoricalMappedPath(str(value))
    if isinstance(value, tuple):
        return tuple(_map_historical_value(item) for item in value)
    if isinstance(value, list):
        return [_map_historical_value(item) for item in value]
    if isinstance(value, dict):
        return {
            _map_historical_value(key): _map_historical_value(item)
            for key, item in value.items()
        }
    if isinstance(value, set):
        return {_map_historical_value(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_map_historical_value(item) for item in value)
    return value


def _default_operational_state_root() -> Path:
    """Locate the retained private operational-state mirror without copying it."""
    fallback = Path(__file__).resolve().parents[3]
    for candidate in Path(__file__).resolve().parents:
        if (candidate / LOCAL_OPERATIONAL_STATE_MARKER).is_dir():
            return candidate
    return fallback


def historical_path(value: str | Path) -> Path:
    """Return one lexical historical path backed by the configured mirror."""
    control_root = operator_control_root().resolve()
    software_factory_root = Path(
        os.environ.get(
            "JAA_HISTORICAL_SOFTWARE_FACTORY_ROOT",
            str(Path(__file__).resolve().parents[3]),
        )
    ).resolve()
    native_jaa_root = Path(
        os.environ.get(
            "JAA_HISTORICAL_NATIVE_ROOT",
            str(Path(__file__).resolve().parent),
        )
    ).resolve()
    operational_state_root = Path(
        os.environ.get(
            "JAA_HISTORICAL_OPERATIONAL_STATE_ROOT",
            str(_default_operational_state_root()),
        )
    ).resolve()
    _HistoricalMappedPath._prefixes = (
        (HISTORICAL_OPERATOR_CONTROL_ROOT, control_root),
        (HISTORICAL_NATIVE_JAA_ROOT, native_jaa_root),
        (HISTORICAL_OPERATIONAL_STATE_ROOT, operational_state_root),
        (HISTORICAL_SOFTWARE_FACTORY_ROOT, software_factory_root),
    )
    return _HistoricalMappedPath(str(value))


def operator_control_root(repository_root: Path | None = None) -> Path:
    """Resolve private certification evidence without binding tests to one host."""
    configured = os.environ.get("JAA_OPERATOR_CONTROL_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    if repository_root is None:
        repository_root = Path(__file__).resolve().parents[2]
    return repository_root.resolve() / ".control"


def operator_control_path(*parts: str, repository_root: Path | None = None) -> Path:
    """Return one path below the resolved operator-control root."""
    return operator_control_root(repository_root).joinpath(*parts)


def rebind_historical_control_paths(
    module: ModuleType,
    *,
    control_root: Path | None = None,
) -> ModuleType:
    """Map frozen Linux I/O while preserving lexical paths and source bytes."""
    resolved_root = (control_root or operator_control_root()).resolve()
    software_factory_root = Path(
        os.environ.get(
            "JAA_HISTORICAL_SOFTWARE_FACTORY_ROOT",
            str(Path(__file__).resolve().parents[3]),
        )
    ).resolve()
    native_jaa_root = Path(
        os.environ.get(
            "JAA_HISTORICAL_NATIVE_ROOT",
            str(Path(__file__).resolve().parent),
        )
    ).resolve()
    operational_state_root = Path(
        os.environ.get(
            "JAA_HISTORICAL_OPERATIONAL_STATE_ROOT",
            str(_default_operational_state_root()),
        )
    ).resolve()
    _HistoricalMappedPath._prefixes = (
        (HISTORICAL_OPERATOR_CONTROL_ROOT, resolved_root),
        (HISTORICAL_NATIVE_JAA_ROOT, native_jaa_root),
        (HISTORICAL_OPERATIONAL_STATE_ROOT, operational_state_root),
        (HISTORICAL_SOFTWARE_FACTORY_ROOT, software_factory_root),
    )
    for name, value in tuple(vars(module).items()):
        setattr(module, name, _map_historical_value(value))
        if not isinstance(value, FunctionType):
            continue
        if value.__defaults__ is not None:
            value.__defaults__ = _map_historical_value(value.__defaults__)
        if value.__kwdefaults__ is not None:
            value.__kwdefaults__ = _map_historical_value(value.__kwdefaults__)
    module.Path = _HistoricalMappedPath
    return module


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
