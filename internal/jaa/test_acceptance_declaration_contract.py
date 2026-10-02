"""Execution-context contract for the repository's shell acceptance declaration."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from testing_repository import clone_jaa_repository


ROOT = Path(__file__).resolve().parent


@pytest.fixture()
def repository(tmp_path: Path) -> Path:
    return clone_jaa_repository(ROOT, tmp_path / "repository")


def test_disposable_repository_preserves_the_market_aligner_jaa_boundary(
    repository: Path,
) -> None:
    discovered = subprocess.run(
        ("git", "rev-parse", "--show-toplevel"),
        cwd=repository,
        text=True,
        capture_output=True,
        check=False,
    )
    assert discovered.returncode == 0, discovered.stderr
    market_aligner_root = Path(discovered.stdout.strip())
    assert repository == market_aligner_root / "internal" / "jaa"
    assert (market_aligner_root / ".git").is_dir()
    assert not (repository / ".git").exists()


def test_acceptance_declaration_runs_directly_and_as_extracted_data(
    repository: Path,
    tmp_path: Path,
) -> None:
    declaration = repository / "acceptance"
    records = [
        line.strip()
        for line in declaration.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(records) == 1
    assert "-c" not in records[0] and "$0" not in records[0]

    runner = repository / "scripts" / "run_acceptance_declaration.py"
    runner.write_text("raise SystemExit(0)\n", encoding="utf-8")
    direct = subprocess.run(
        ("bash", str(declaration)),
        cwd=tmp_path,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert direct.returncode == 0, direct.stderr
    extracted = subprocess.run(
        ("/bin/sh", "-c", records[0]),
        cwd=repository,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert extracted.returncode == 0, extracted.stderr
