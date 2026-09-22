#!/usr/bin/env python3
"""Create or verify the clean-head receipt for a JAA gate environment."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path


SCHEMA = "jaa.gate-environment-receipt.v2"
RECEIPT_NAME = ".jaa-gate-environment-v2.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args),
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _clean_head(root: Path) -> tuple[str, str, int]:
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("gate environment requires the exact clean committed source head")
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    epoch_text = _git(root, "show", "-s", "--format=%ct", "HEAD")
    if not SHA256.fullmatch(head) and not re.fullmatch(r"[0-9a-f]{40}", head):
        raise SystemExit("source HEAD identity is invalid")
    if not SHA256.fullmatch(tree) and not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise SystemExit("source tree identity is invalid")
    return head, tree, int(epoch_text)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _installed_manifest() -> tuple[str, str]:
    from career_automation.protected_corpus_binding import installed_distribution_manifest

    return installed_distribution_manifest()


def _market_manifest() -> str:
    from career_automation.protected_corpus_binding import installed_distribution_manifest

    return installed_distribution_manifest(
        distribution_name="market-aligner", expected_version="0.1.0.dev0"
    )[1]


def _canonical(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _browser_cache(value: str | None) -> str | None:
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise SystemExit("browser cache receipt requires an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SystemExit("browser cache receipt path is unavailable") from exc
    if not resolved.is_dir():
        raise SystemExit("browser cache receipt path is not a directory")
    return str(resolved)


def _expected(root: Path, *, wheel: Path, market_wheel: Path, browser_cache: str | None) -> dict[str, object]:
    head, tree, epoch = _clean_head(root)
    version, installed_manifest = _installed_manifest()
    return {
        "bootstrap_lock_sha256": _sha256(root / "requirements-bootstrap.lock"),
        "browser_cache": _browser_cache(browser_cache),
        "distribution": "job-application-automation",
        "distribution_version": version,
        "installed_manifest_sha256": installed_manifest,
        "market_installed_manifest_sha256": _market_manifest(),
        "playwright_version": importlib.metadata.version("playwright"),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "schema_version": SCHEMA,
        "source_date_epoch": epoch,
        "source_head": head,
        "source_tree": tree,
        "test_lock_sha256": _sha256(root / "requirements-test.lock"),
        "wheel_sha256": _sha256(wheel),
        "market_wheel_sha256": _sha256(market_wheel),
    }


def _receipt_path() -> Path:
    if sys.prefix == sys.base_prefix:
        raise SystemExit("gate environment receipt requires an isolated virtual environment")
    return Path(sys.prefix).resolve() / RECEIPT_NAME


def write(root: Path, wheel: Path, market_wheel: Path, browser_cache: str | None) -> None:
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
        raise SystemExit("gate environment receipt requires exact CPython 3.12.13")
    document = _expected(root, wheel=wheel, market_wheel=market_wheel, browser_cache=browser_cache)
    if document["playwright_version"] != "1.62.0":
        raise SystemExit("gate environment receipt requires Playwright 1.62.0")
    path = _receipt_path()
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(_canonical(document))
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    print(f"gate environment receipt written: {path}")


def verify(root: Path, browser_cache: str | None) -> None:
    path = _receipt_path()
    try:
        value = path.read_bytes()
        document = json.loads(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("gate environment receipt is unavailable or malformed") from exc
    if type(document) is not dict or _canonical(document) != value:
        raise SystemExit("gate environment receipt is not canonical JSON")
    required = {
        "bootstrap_lock_sha256",
        "browser_cache",
        "distribution",
        "distribution_version",
        "installed_manifest_sha256",
        "playwright_version",
        "python_implementation",
        "python_version",
        "schema_version",
        "source_date_epoch",
        "source_head",
        "source_tree",
        "test_lock_sha256",
        "wheel_sha256",
        "market_wheel_sha256",
        "market_installed_manifest_sha256",
    }
    if set(document) != required:
        raise SystemExit("gate environment receipt fields differ")
    head, tree, epoch = _clean_head(root)
    version, installed_manifest = _installed_manifest()
    expected = {
        "bootstrap_lock_sha256": _sha256(root / "requirements-bootstrap.lock"),
        "browser_cache": _browser_cache(browser_cache),
        "distribution": "job-application-automation",
        "distribution_version": version,
        "installed_manifest_sha256": installed_manifest,
        "market_installed_manifest_sha256": _market_manifest(),
        "playwright_version": importlib.metadata.version("playwright"),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "schema_version": SCHEMA,
        "source_date_epoch": epoch,
        "source_head": head,
        "source_tree": tree,
        "test_lock_sha256": _sha256(root / "requirements-test.lock"),
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise SystemExit("gate environment does not match its clean-head receipt")
    if not all(SHA256.fullmatch(str(document[key])) for key in ("wheel_sha256", "market_wheel_sha256")):
        raise SystemExit("gate environment wheel identity is invalid")
    print(
        "gate environment verified: "
        f"{head} wheel sha256:{document['wheel_sha256']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--market-wheel", type=Path)
    parser.add_argument("--browser-cache")
    args = parser.parse_args()
    root = args.repository_root.resolve(strict=True)
    if args.write:
        if args.wheel is None or args.market_wheel is None:
            parser.error("--write requires --wheel and --market-wheel")
        write(root, args.wheel.resolve(strict=True), args.market_wheel.resolve(strict=True), args.browser_cache)
    else:
        if args.wheel is not None or args.market_wheel is not None:
            parser.error("--wheel is valid only with --write")
        verify(root, args.browser_cache)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
