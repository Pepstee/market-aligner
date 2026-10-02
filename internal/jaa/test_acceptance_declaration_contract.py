"""Execution-context controls for the declared JAA acceptance shell."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent


@pytest.fixture()
def repository() -> Path:
    return ROOT


def test_repository_preserves_the_market_aligner_jaa_boundary(
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
    original_runner = runner.read_bytes()
    shim_directory = tmp_path / "bin"
    shim_directory.mkdir()
    shim = shim_directory / "python3"
    shim.write_text(
        "#!/bin/sh\n"
        "[ \"$#\" -eq 1 ] || exit 90\n"
        "if [ \"$1\" = \"$PYTHON3_EXPECTED_RUNNER\" ]; then\n"
        "  printf '%s\\t%s\\t%s\\n' direct \"$PWD\" \"$1\" >> \"$PYTHON3_TEST_LOG\"\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = scripts/run_acceptance_declaration.py ]; then\n"
        "  printf '%s\\t%s\\t%s\\n' extracted \"$PWD\" \"$1\" >> \"$PYTHON3_TEST_LOG\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 91\n",
        encoding="utf-8",
    )
    shim.chmod(0o700)
    invocations = tmp_path / "python3-invocations.txt"
    environment = {
        **os.environ,
        "PATH": f"{shim_directory}{os.pathsep}{os.defpath}",
        "PYTHON3_EXPECTED_RUNNER": str(runner),
        "PYTHON3_TEST_LOG": str(invocations),
    }
    direct = subprocess.run(
        ("bash", str(declaration)),
        cwd=tmp_path,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert direct.returncode == 0, direct.stderr
    extracted = subprocess.run(
        ("/bin/sh", "-c", records[0]),
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert extracted.returncode == 0, extracted.stderr
    assert invocations.read_text(encoding="utf-8").splitlines() == [
        f"direct\t{tmp_path}\t{runner}",
        f"extracted\t{repository}\tscripts/run_acceptance_declaration.py",
    ]
    assert runner.read_bytes() == original_runner
