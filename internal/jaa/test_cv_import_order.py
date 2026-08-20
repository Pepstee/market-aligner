from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def _fresh_imports(program: str) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    completed = subprocess.run(
        (sys.executable, "-c", program),
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_candidate_factory_then_composition_service_imports_cleanly() -> None:
    _fresh_imports(
        "\n".join(
            (
                "from career_automation.candidate_application_factory import CandidateApplicationPackage as FactoryPackage",
                "from cv_generation.service import CandidateApplicationPackage as ServicePackage",
                "from cv_generation import run_cv_composition_orchestration",
                "assert FactoryPackage is ServicePackage",
                "assert callable(run_cv_composition_orchestration)",
            )
        )
    )


def test_composition_service_then_candidate_factory_imports_cleanly() -> None:
    _fresh_imports(
        "\n".join(
            (
                "from cv_generation.service import CandidateApplicationPackage as ServicePackage",
                "from career_automation.candidate_application_factory import CandidateApplicationPackage as FactoryPackage",
                "from cv_generation import CVCompositionOrchestrationResult",
                "assert FactoryPackage is ServicePackage",
                "assert CVCompositionOrchestrationResult.__module__ == 'cv_generation.service'",
            )
        )
    )

