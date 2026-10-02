"""Independent runtime-selection regressions for the Scrapling sidecar."""

from __future__ import annotations

from pathlib import Path

import pytest
from scraper.scrapling_client import ScraplingClient as LegacyScraplingClient
from market_aligner.collectors.scrapling_client import ScraplingClient as CanonicalScraplingClient


@pytest.fixture(params=(LegacyScraplingClient, CanonicalScraplingClient))
def client_type(request):
    return request.param


def test_explicit_runtime_python_overrides_shared_runtime_environment(
    tmp_path: Path, monkeypatch, client_type,
) -> None:
    root = tmp_path / "repository"
    explicit = tmp_path / "explicit-sidecar" / "bin" / "python"
    shared_runtime = tmp_path / "shared-sidecar"
    monkeypatch.setenv("AGENTIC_SCRAPLING_RUNTIME_DIR", str(shared_runtime))

    client = client_type(root, {"runtime_python": str(explicit)})

    assert client.runtime == explicit


def test_shared_runtime_environment_overrides_project_default_when_config_absent(
    tmp_path: Path, monkeypatch, client_type,
) -> None:
    root = tmp_path / "repository"
    shared_runtime = tmp_path / "shared-sidecar"
    monkeypatch.setenv("AGENTIC_SCRAPLING_RUNTIME_DIR", str(shared_runtime))

    client = client_type(root)

    assert client.runtime == shared_runtime / "bin" / "python"
    assert client.runtime != root / ".venv-scrapling" / "bin" / "python"


def test_project_local_runtime_remains_fallback_without_config_or_environment(
    tmp_path: Path, monkeypatch, client_type,
) -> None:
    root = tmp_path / "repository"
    monkeypatch.delenv("AGENTIC_SCRAPLING_RUNTIME_DIR", raising=False)

    client = client_type(root)

    assert client.runtime == root / ".venv-scrapling" / "bin" / "python"
