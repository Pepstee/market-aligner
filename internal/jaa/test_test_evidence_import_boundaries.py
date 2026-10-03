"""Black-box regressions for test-evidence local-source boundary controls."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import sysconfig
import tomllib
from pathlib import Path

import pytest

import test_generate_test_evidence as public_cli


PROJECT_ROOT = Path(__file__).resolve().parent
GENERATOR = PROJECT_ROOT / "scripts" / "generate-test-evidence.py"


def _generator_module():
    spec = importlib.util.spec_from_file_location(
        "import_boundary_generator", GENERATOR
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = _generator_module()


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def test_isolated_checkout_prefers_its_root_over_conflicting_activated_editable_install(
    tmp_path: Path,
) -> None:
    """No PYTHONPATH may be needed to reject an activated foreign editable package."""
    foreign = tmp_path / "foreign-editable"
    package = foreign / "src" / "skeleton"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("LOCAL = False\n", encoding="utf-8")
    (foreign / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==80.9.0"]\n'
        'build-backend = "setuptools.build_meta"\n'
        '[project]\nname = "conflicting-skeleton-editable"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    venv = tmp_path / "activated-locked-cpython312"
    subprocess.run((sys.executable, "-m", "venv", str(venv)), check=True)
    python = _venv_python(venv)
    purelib = Path(
        subprocess.run(
            (str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"),
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
    )
    assert purelib.is_dir()
    dependency_depot = Path(sysconfig.get_paths()["purelib"]).resolve()
    dependency_path = purelib / "zz_dependency_depot.pth"
    assert not dependency_path.exists()
    dependency_path.write_text(f"{dependency_depot}\n", encoding="utf-8")
    build_requirements = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["build-system"]["requires"]
    assert build_requirements == ["setuptools==80.9.0"]
    environment = public_cli._generator_environment(
        python,
        runner_directory=None,
        use_pythonpath=False,
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["VIRTUAL_ENV"] = str(venv)
    locked_versions = {
        line.split("==", 1)[0]: line.split("==", 1)[1]
        for line in (PROJECT_ROOT / "requirements-test.lock")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    locked_versions["setuptools"] = build_requirements[0].split("==", 1)[1]
    version_probe = (
        "import importlib.metadata as metadata, json; "
        f"print(json.dumps({{name: metadata.version(name) for name in {tuple(locked_versions)!r}}}))"
    )
    observed_versions = json.loads(
        subprocess.run(
            (str(python), "-c", version_probe),
            env=environment,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
    )
    assert observed_versions == locked_versions
    subprocess.run(
        (
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-build-isolation",
            "--no-deps",
            "--editable",
            str(foreign),
        ),
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert "PYTHONPATH" not in environment

    distribution = json.loads(
        subprocess.run(
            (
                str(python),
                "-c",
                "import importlib.metadata as metadata, json; "
                "print(metadata.distribution('conflicting-skeleton-editable').read_text('direct_url.json'))",
            ),
            env=environment,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
    )
    assert distribution["dir_info"] == {"editable": True}
    assert distribution["url"] == foreign.resolve().as_uri()

    origin_probe = subprocess.run(
        (
            str(python),
            "-c",
            "import importlib.util, json, sys; "
            "assert 'skeleton' not in sys.modules; "
            "spec = importlib.util.find_spec('skeleton'); "
            "assert spec is not None and spec.origin is not None; "
            "assert 'skeleton' not in sys.modules; "
            "print(json.dumps({'origin': spec.origin, 'loaded': 'skeleton' in sys.modules}))",
        ),
        env=environment,
        cwd=tmp_path,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    assert json.loads(origin_probe.stdout) == {
        "origin": str((package / "__init__.py").resolve()),
        "loaded": False,
    }
    foreign_import = subprocess.run(
        (
            str(python),
            "-c",
            "import json, skeleton; "
            "print(json.dumps({'origin': skeleton.__file__, 'local': skeleton.LOCAL}))",
        ),
        env=environment,
        cwd=tmp_path,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    assert json.loads(foreign_import.stdout) == {
        "origin": str((package / "__init__.py").resolve()),
        "local": False,
    }

    complete = "================ 2 passed in 0.01s ================"
    career = "================ 2 passed in 0.01s ================"
    public_cli._write_scripted_pytest(purelib, complete, career)
    with public_cli._canonical_public_cli_session(
        tmp_path,
        complete,
        career,
        python=python,
        runner_directory=purelib,
        use_pythonpath=False,
    ) as session:
        session.environment["VIRTUAL_ENV"] = str(venv)
        assert session.environment["VIRTUAL_ENV"] == str(venv)
        assert "PYTHONPATH" not in session.environment
        run = public_cli._run_canonical_public_cli_in_session(session)

    assert run.returncode == 0, run.stderr
    assert run.receipt_path is not None
    assert run.receipt_payload is not None
    assert run.stdout == f"{run.receipt_path}\n"
    receipt = json.loads(run.receipt_payload)
    rendered = json.dumps(receipt, sort_keys=True)
    assert receipt["suites"] == [
        {
            "name": "complete",
            "argv": ["python", "-m", "pytest", "-q"],
            "counts": {"collected": 2, "passed": 2, "skipped": 0, "failed": 0},
        },
        {
            "name": "career_automation",
            "argv": ["python", "-m", "pytest", "-q", "career_automation"],
            "counts": {"collected": 2, "passed": 2, "skipped": 0, "failed": 0},
            "historical_baseline_passed": 65,
        },
    ]
    assert str(tmp_path) not in rendered
    assert str(python) not in rendered
    assert all(
        not Path(arg).is_absolute()
        for suite in receipt["suites"]
        for arg in suite["argv"]
    )
    assert [
        json.loads(line)
        for line in (run.runner_directory / "invocations.jsonl").read_text().splitlines()
    ] == [
        {"argv": ["-q"], "cwd": str(public_cli.REPOSITORY)},
        {"argv": ["-q", "career_automation"], "cwd": str(public_cli.REPOSITORY)},
    ]


def test_public_generator_refuses_an_apparent_local_source_symlink_escape_before_receipt(
    tmp_path: Path,
) -> None:
    """The complete process must reject a local-looking source that escapes checkout."""
    external_source = tmp_path / "outside-checkout" / "__init__.py"
    external_source.parent.mkdir()
    external_source.write_text("ESCAPED = True\n", encoding="utf-8")
    source_path = PROJECT_ROOT / "skeleton" / "__init__.py"
    ignore_path = PROJECT_ROOT / ".gitignore"
    receipt_directory = public_cli.REPOSITORY / "runtime_evidence" / "pytest"
    assert not receipt_directory.exists()
    original_source = source_path.read_bytes()
    original_source_mode = stat.S_IMODE(source_path.stat().st_mode)
    original_ignore = ignore_path.read_bytes()
    original_ignore_mode = stat.S_IMODE(ignore_path.stat().st_mode)
    assert b"skeleton/__init__.py" not in original_ignore.splitlines()
    base_head = public_cli.inplace_fixture._git(
        "rev-parse", public_cli.inplace_fixture.BASE_BRANCH
    )
    assert public_cli.inplace_fixture._git_path_mode(
        base_head, "internal/jaa/skeleton/__init__.py"
    ) == "100644"
    assert public_cli.inplace_fixture._git_path_mode(
        base_head, "internal/jaa/.gitignore"
    ) == "100644"

    complete = "================ 2 passed in 0.01s ================"
    career = "================ 2 passed in 0.01s ================"
    sequence = public_cli.inplace_fixture.TEST_EVIDENCE_LOCAL_IMPORT_SYMLINK_COMMIT_SEQUENCE
    with public_cli._canonical_public_cli_session(
        tmp_path,
        complete,
        career,
        python=sys.executable,
        use_pythonpath=False,
        commit_sequence=sequence,
    ) as session:
        state = session.state
        ignore_content = original_ignore + (
            b"" if original_ignore.endswith(b"\n") else b"\n"
        ) + b"skeleton/__init__.py\n"
        public_cli.inplace_fixture._commit_mutation(
            state,
            "internal/jaa/.gitignore",
            ignore_content.decode("utf-8"),
            "evidence-import-symlink",
        )
        public_cli.inplace_fixture._commit_path_change(
            state,
            "internal/jaa/skeleton/__init__.py",
            "deleted",
            None,
            "evidence-import-symlink",
        )
        assert ignore_path.read_bytes() == ignore_content
        assert stat.S_IMODE(ignore_path.stat().st_mode) == original_ignore_mode
        assert not source_path.exists() and not source_path.is_symlink()
        public_cli.inplace_fixture._assert_admission(state.branch, state.head, False)
        try:
            source_path.symlink_to(external_source)
            assert source_path.is_symlink()
            assert os.readlink(source_path) == str(external_source)
            public_cli.inplace_fixture._git(
                "check-ignore", "--quiet", "internal/jaa/skeleton/__init__.py"
            )
            public_cli.inplace_fixture._assert_admission(state.branch, state.head, False)
            run = public_cli._run_canonical_public_cli_in_session(session)
        finally:
            public_cli.inplace_fixture._assert_admission(state.branch, state.head, False)
            if not source_path.is_symlink() or os.readlink(source_path) != str(external_source):
                raise AssertionError("ignored symlink changed before exact cleanup")
            if external_source.read_text(encoding="utf-8") != "ESCAPED = True\n":
                raise AssertionError("synthetic symlink target changed before cleanup")
            source_path.unlink()
            public_cli.inplace_fixture._assert_admission(state.branch, state.head, False)

    assert run.returncode != 0
    assert "local project import 'skeleton' does not resolve to this repository" in run.stderr
    assert run.receipt_path is None
    assert not receipt_directory.exists()
    assert source_path.is_file() and not source_path.is_symlink()
    assert source_path.read_bytes() == original_source
    assert stat.S_IMODE(source_path.stat().st_mode) == original_source_mode
    assert ignore_path.read_bytes() == original_ignore
    assert stat.S_IMODE(ignore_path.stat().st_mode) == original_ignore_mode


def test_local_source_file_rejects_a_root_first_module_resolving_outside_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "apparent-root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "__init__.py"
    target.write_text("ESCAPED = True\n", encoding="utf-8")
    package = root / "skeleton"
    package.mkdir()
    (package / "__init__.py").symlink_to(target)
    monkeypatch.setattr(VERIFIER, "ROOT", root)

    with pytest.raises(
        VERIFIER.EvidenceError, match="does not resolve to this repository"
    ):
        VERIFIER.local_source_file("skeleton")


def test_local_source_file_still_accepts_normal_source_and_rejects_missing_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "normal-root"
    package = root / "skeleton"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_text("LOCAL = True\n", encoding="utf-8")
    monkeypatch.setattr(VERIFIER, "ROOT", root)

    assert VERIFIER.local_source_file("skeleton") == source.resolve()
    with pytest.raises(
        VERIFIER.EvidenceError, match="does not resolve to this repository"
    ):
        VERIFIER.local_source_file("missing_local_module")
