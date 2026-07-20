"""Black-box regressions for test-evidence local-source boundary controls."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent
GENERATOR = PROJECT_ROOT / "scripts" / "generate-test-evidence.py"


def _generator_module():
    spec = importlib.util.spec_from_file_location("import_boundary_generator", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = _generator_module()


def _write_isolated_checkout(root: Path) -> None:
    """Create a clean, runnable checkout whose test runner is deterministic."""
    script = root / "scripts" / GENERATOR.name
    script.parent.mkdir(parents=True)
    shutil.copy2(GENERATOR, script)
    (root / "skeleton").mkdir()
    (root / "skeleton" / "__init__.py").write_text("LOCAL = True\n", encoding="utf-8")
    requirements = []
    for raw in (PROJECT_ROOT / "requirements-test.lock").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            distribution = line.split("==", 1)[0]
            requirements.append(f"{distribution}=={importlib.metadata.version(distribution)}")
    (root / "requirements-test.lock").write_text("\n".join(requirements) + "\n", encoding="utf-8")
    (root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    (root / "pytest.py").write_text(
        "import sys\n"
        "print('==== 2 passed in 0.01s ====')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(("git", "add", "."), cwd=root, check=True)
    subprocess.run(
        ("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "isolated checkout"),
        cwd=root,
        check=True,
    )


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def test_isolated_checkout_prefers_its_root_over_conflicting_activated_editable_install(
    tmp_path: Path,
) -> None:
    """No PYTHONPATH may be needed to reject an activated foreign editable package."""
    checkout = tmp_path / "isolated-checkout"
    checkout.mkdir()
    _write_isolated_checkout(checkout)

    foreign = tmp_path / "foreign-editable"
    (foreign / "skeleton").mkdir(parents=True)
    (foreign / "skeleton" / "__init__.py").write_text("LOCAL = False\n", encoding="utf-8")
    (foreign / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'conflicting-skeleton-editable'\nversion = '1.0'\n",
        encoding="utf-8",
    )
    venv = tmp_path / "activated-locked-cpython312"
    subprocess.run((sys.executable, "-m", "venv", "--system-site-packages", str(venv)), check=True)
    python = _venv_python(venv)
    subprocess.run(
        (str(python), "-m", "pip", "install", "--requirement", str(checkout / "requirements-test.lock")),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        (str(python), "-m", "pip", "install", "--no-build-isolation", "--no-deps", "--editable", str(foreign)),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["VIRTUAL_ENV"] = str(venv)
    environment["PATH"] = str(python.parent) + os.pathsep + environment.get("PATH", "")

    foreign_import = subprocess.run(
        (str(python), "-c", "import skeleton; print(skeleton.__file__)"),
        cwd=tmp_path,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    assert Path(foreign_import.stdout.strip()).resolve().is_relative_to(foreign.resolve())

    completed = subprocess.run(
        (str(python), str(checkout / "scripts" / GENERATOR.name)),
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads((checkout / completed.stdout.strip()).read_text(encoding="utf-8"))
    rendered = json.dumps(receipt, sort_keys=True)
    assert receipt["suites"] == [
        {"name": "complete", "argv": ["python", "-m", "pytest", "-q"],
         "counts": {"collected": 2, "passed": 2, "skipped": 0, "failed": 0}},
        {"name": "career_automation", "argv": ["python", "-m", "pytest", "-q", "career_automation"],
         "counts": {"collected": 2, "passed": 2, "skipped": 0, "failed": 0},
         "historical_baseline_passed": 65},
    ]
    assert str(tmp_path) not in rendered
    assert str(python) not in rendered
    assert all(not Path(arg).is_absolute() for suite in receipt["suites"] for arg in suite["argv"])


def test_public_generator_refuses_an_apparent_local_source_symlink_escape_before_receipt(
    tmp_path: Path,
) -> None:
    """The complete process must reject a local-looking source that escapes checkout."""
    checkout = tmp_path / "isolated-checkout"
    checkout.mkdir()
    _write_isolated_checkout(checkout)

    external_source = tmp_path / "outside-checkout" / "__init__.py"
    external_source.parent.mkdir()
    external_source.write_text("ESCAPED = True\n", encoding="utf-8")
    local_source = checkout / "skeleton" / "__init__.py"
    subprocess.run(("git", "rm", "--cached", "skeleton/__init__.py"), cwd=checkout, check=True)
    (checkout / ".gitignore").write_text(
        ".venv/\nskeleton/__init__.py\n", encoding="utf-8"
    )
    local_source.unlink()
    local_source.symlink_to(external_source)
    subprocess.run(("git", "add", ".gitignore"), cwd=checkout, check=True)
    subprocess.run(
        (
            "git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "ignore local skeleton source",
        ),
        cwd=checkout,
        check=True,
    )

    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(checkout / "scripts" / GENERATOR.name)),
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode != 0
    assert "local project import 'skeleton' does not resolve to this repository" in completed.stderr
    assert not (checkout / "runtime_evidence" / "pytest").exists()


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

    with pytest.raises(VERIFIER.EvidenceError, match="does not resolve to this repository"):
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
    with pytest.raises(VERIFIER.EvidenceError, match="does not resolve to this repository"):
        VERIFIER.local_source_file("missing_local_module")
