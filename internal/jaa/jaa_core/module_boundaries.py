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
    # Core evidence, identity, state, and policy.
    "career_automation/admission_evidence.py": "jaa_core",
    "career_automation/application_archive.py": "jaa_core",
    "career_automation/application_strategy.py": "jaa_core",
    "career_automation/candidate_authority.py": "jaa_core",
    "career_automation/candidate_contact_authority.py": "jaa_core",
    "career_automation/candidate_graph.py": "jaa_core",
    "career_automation/candidate_release_authority.py": "jaa_core",
    "career_automation/database.py": "jaa_core",
    "career_automation/employer_research.py": "jaa_core",
    "career_automation/engine.py": "jaa_core",
    "career_automation/evidence_matching.py": "jaa_core",
    "career_automation/gap_optimizer.py": "jaa_core",
    "career_automation/lifecycle.py": "jaa_core",
    "career_automation/models.py": "jaa_core",
    "career_automation/production_queue.py": "jaa_core",
    "career_automation/vacancy_identity.py": "jaa_core",
    # Employer-facing composition and document assurance.
    "career_automation/adversarial_recruiter.py": "cv_generation",
    "career_automation/adversarial_recruiter_archive.py": "cv_generation",
    "career_automation/adversarial_recruiter_runtime.py": "cv_generation",
    "career_automation/application_artifacts.py": "cv_generation",
    "career_automation/application_compiler.py": "cv_generation",
    "career_automation/application_preview.py": "cv_generation",
    "career_automation/application_sanity_review.py": "cv_generation",
    "career_automation/candidate_application_factory.py": "cv_generation",
    "career_automation/candidate_generation_worker.py": "cv_generation",
    "career_automation/external_document_assurance.py": "cv_generation",
    "career_automation/rendering.py": "cv_generation",
    # Provider binding, browser operation, and consequential execution.
    "career_automation/ashby_live_adapter.py": "form_filling",
    "career_automation/browser_executor.py": "form_filling",
    "career_automation/browser_workflows.py": "form_filling",
    "career_automation/candidate_release_gate.py": "form_filling",
    "career_automation/gmail_confirmation.py": "form_filling",
    "career_automation/greenhouse_live_discovery.py": "form_filling",
    "career_automation/live_vacancy_discovery.py": "form_filling",
    "career_automation/personio_live_adapter.py": "form_filling",
    "career_automation/production_attempt.py": "form_filling",
    "career_automation/production_form_binding.py": "form_filling",
    "career_automation/production_ats_executor.py": "form_filling",
    "career_automation/production_runner.py": "form_filling",
    "career_automation/provider_observation_authority.py": "form_filling",
    "career_automation/provider_observation_capture.py": "form_filling",
    "career_automation/recruitee_live_adapter.py": "form_filling",
    "career_automation/release_gate.py": "form_filling",
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
