"""Machine-checkable ownership and dependency rules for the JAA split."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Mapping


MODULE_DEPENDENCIES: Mapping[str, frozenset[str]] = {
    "jaa_core": frozenset(),
    "cv_generation": frozenset({"jaa_core"}),
    "form_filling": frozenset({"jaa_core", "cv_generation"}),
}

LEGACY_OWNERSHIP: Mapping[str, str] = {
    "career_automation/application_compiler.py": "cv_generation",
    "career_automation/candidate_application_factory.py": "cv_generation",
    "career_automation/rendering.py": "cv_generation",
    "career_automation/external_document_assurance.py": "cv_generation",
    "career_automation/browser_executor.py": "form_filling",
    "career_automation/browser_workflows.py": "form_filling",
    "career_automation/production_form_binding.py": "form_filling",
    "career_automation/production_ats_executor.py": "form_filling",
    "career_automation/evidence_matching.py": "jaa_core",
    "career_automation/models.py": "jaa_core",
    "career_automation/lifecycle.py": "jaa_core",
    "career_automation/database.py": "jaa_core",
}


def assert_public_module_boundaries(repository: Path) -> None:
    """Reject dependencies that reverse the declared three-module layering."""
    for module, allowed in MODULE_DEPENDENCIES.items():
        for path in sorted((repository / module).glob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                imported: tuple[str, ...] = ()
                if isinstance(node, ast.Import):
                    imported = tuple(row.name.split(".", 1)[0] for row in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported = (node.module.split(".", 1)[0],)
                for dependency in imported:
                    if dependency in MODULE_DEPENDENCIES and dependency not in allowed:
                        raise ValueError(
                            f"{path.relative_to(repository)} reverses module boundary: "
                            f"{module} -> {dependency}"
                        )


__all__ = [
    "LEGACY_OWNERSHIP",
    "MODULE_DEPENDENCIES",
    "assert_public_module_boundaries",
]
