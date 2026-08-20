import tomllib
from pathlib import Path

from career_automation.application_compiler import (
    CandidateContact as LegacyCandidateContact,
)
from jaa_core.contracts import CandidateContact
from jaa_core.module_boundaries import (
    LEGACY_OWNERSHIP,
    MODULE_DEPENDENCIES,
    assert_public_module_boundaries,
)


ROOT = Path(__file__).resolve().parent


def test_public_modules_obey_one_way_dependencies() -> None:
    assert_public_module_boundaries(ROOT)
    assert MODULE_DEPENDENCIES["jaa_core"] == frozenset()
    assert "form_filling" not in MODULE_DEPENDENCIES["cv_generation"]


def test_legacy_files_have_one_explicit_owner_and_exist() -> None:
    assert len(LEGACY_OWNERSHIP) == len(set(LEGACY_OWNERSHIP))
    assert set(LEGACY_OWNERSHIP.values()) == {
        "jaa_core",
        "cv_generation",
        "form_filling",
    }
    assert all((ROOT / path).is_file() for path in LEGACY_OWNERSHIP)


def test_core_owns_candidate_contact_without_reverse_legacy_import() -> None:
    contracts_source = (ROOT / "jaa_core/contracts.py").read_text(encoding="utf-8")
    assert "career_automation.application_compiler" not in contracts_source
    assert CandidateContact.__module__ == "jaa_core.contracts"
    assert LegacyCandidateContact is CandidateContact


def test_consequential_legacy_capabilities_have_declared_owners() -> None:
    expected = {
        "career_automation/candidate_authority.py": "jaa_core",
        "career_automation/candidate_contact_authority.py": "jaa_core",
        "career_automation/candidate_graph.py": "jaa_core",
        "career_automation/application_strategy.py": "jaa_core",
        "career_automation/adversarial_recruiter.py": "cv_generation",
        "career_automation/application_artifacts.py": "cv_generation",
        "career_automation/application_compiler.py": "cv_generation",
        "career_automation/candidate_application_factory.py": "cv_generation",
        "career_automation/external_document_assurance.py": "cv_generation",
        "career_automation/rendering.py": "cv_generation",
        "career_automation/ashby_live_adapter.py": "form_filling",
        "career_automation/browser_executor.py": "form_filling",
        "career_automation/candidate_release_gate.py": "form_filling",
        "career_automation/personio_live_adapter.py": "form_filling",
        "career_automation/production_ats_executor.py": "form_filling",
        "career_automation/production_form_binding.py": "form_filling",
        "career_automation/production_runner.py": "form_filling",
        "career_automation/recruitee_live_adapter.py": "form_filling",
        "career_automation/release_gate.py": "form_filling",
    }
    assert {path: LEGACY_OWNERSHIP.get(path) for path in expected} == expected


def test_internal_distribution_has_unambiguous_identity_and_runtime_contract() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert project["name"] == "job-application-automation"
    assert project["requires-python"] == ">=3.12,<3.13"
    assert "playwright==1.62.0" in project["dependencies"]
    assert "playwright==1.62.0" not in project["optional-dependencies"]["full"]
    assert set(project["scripts"]).isdisjoint({"market-aligner", "uk-job-matcher"})
    assert all(command.startswith("jaa-") for command in project["scripts"])

    lock = (ROOT / "requirements-test.lock").read_text(encoding="utf-8").splitlines()
    assert "playwright==1.62.0" in lock
    assert "greenlet==3.5.4" in lock
    assert "pyee==13.0.1" in lock
