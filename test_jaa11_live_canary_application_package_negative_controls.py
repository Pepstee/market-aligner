"""Fail-closed controls for fixture-only application-package composition."""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.live_canary_application_package import (
    compose_application_package_dry_run,
)
from career_automation.live_canary_operator_answer_composition import (
    OperatorAnswerComposition,
)
from career_automation.live_canary_operator_answers import (
    ApprovedEvidenceReference,
    OperatorAnswerRequest,
)
from career_automation.release_gate import compile_release_manifest
from test_jaa08_independent_acceptance import _validations
from test_jaa11_live_canary_application_package import (
    _package,
    _package_inputs,
)
from test_jaa11_live_canary_operator_answer_composition import _composition
from test_jaa11_live_canary_operator_answers import _hash


MODULE = (
    Path(__file__).resolve().parent
    / "career_automation/live_canary_application_package.py"
)


def _flip_first_nibble(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]


def test_selected_vacancy_identity_mismatch_fails_closed() -> None:
    answers, source, artifacts, manifest = _package_inputs(
        snapshot_vacancy_identity="vacancy:different"
    )
    with pytest.raises(ValueError, match="selected vacancy identity"):
        compose_application_package_dry_run(
            answers, source, artifacts, manifest
        )


def test_vacancy_content_hash_mismatch_fails_closed() -> None:
    answers, source, artifacts, manifest = _package_inputs()
    binding = replace(manifest.binding, vacancy_sha256="0" * 64)
    changed = compile_release_manifest(binding, _validations(binding))
    with pytest.raises(ValueError, match="vacancy content hash"):
        compose_application_package_dry_run(
            answers, source, artifacts, changed
        )


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("application_source_sha256", "source content hash"),
        ("artifact_set_sha256", "artifact-set hash"),
    ),
)
def test_release_binding_cannot_point_at_different_application_inputs(
    field: str,
    message: str,
) -> None:
    answers, source, artifacts, manifest = _package_inputs()
    binding = replace(manifest.binding, **{field: "0" * 64})
    changed = compile_release_manifest(binding, _validations(binding))
    with pytest.raises(ValueError, match=message):
        compose_application_package_dry_run(
            answers, source, artifacts, changed
        )


def test_tampered_release_manifest_and_artifacts_fail_their_replays() -> None:
    answers, source, artifacts, manifest = _package_inputs()
    with pytest.raises(ValueError, match="release manifest differs"):
        compose_application_package_dry_run(
            answers,
            source,
            artifacts,
            replace(
                manifest,
                release_manifest_sha256=_flip_first_nibble(
                    manifest.release_manifest_sha256
                ),
            ),
        )
    with pytest.raises(ValueError, match="artifact-set identity"):
        compose_application_package_dry_run(
            answers,
            source,
            replace(
                artifacts,
                artifact_set_sha256=_flip_first_nibble(
                    artifacts.artifact_set_sha256
                ),
            ),
            manifest,
        )


def test_fail_closed_answer_blocks_the_entire_package() -> None:
    sponsorship = OperatorAnswerRequest(
        topic="work_authorisation",
        answer_kind="boolean",
        subtopic="sponsorship",
        jurisdiction="GB",
        evidence=ApprovedEvidenceReference(
            source_kind="identity_work_rights_ledger",
            source_sha256=_hash("fixture-work-rights"),
            topic="work_authorisation",
            exact_claim="current_work_authorisation",
            jurisdiction="GB",
        ),
    )
    with pytest.raises(ValueError, match="every composed answer"):
        _package(sponsorship)


def test_work_authorisation_jurisdiction_must_match_release_binding() -> None:
    answers, source, artifacts, manifest = _package_inputs(
        request_jurisdiction="United Kingdom"
    )
    with pytest.raises(ValueError, match="jurisdiction differs"):
        compose_application_package_dry_run(
            answers, source, artifacts, manifest
        )


def test_exact_types_reject_dict_impostors_and_subclasses() -> None:
    inputs = list(_package_inputs())
    for index in range(4):
        changed = list(inputs)
        changed[index] = {}
        with pytest.raises(ValueError, match="exact"):
            compose_application_package_dry_run(*changed)

    base = _composition()

    class AnswerCompositionSubclass(OperatorAnswerComposition):
        pass

    subclass = AnswerCompositionSubclass(**vars(base))
    inputs[0] = subclass
    with pytest.raises(ValueError, match="exact answer composition"):
        compose_application_package_dry_run(*inputs)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("may_submit", True),
        ("release_token", "jaa08.not-authorized"),
        ("package_used_for_external_submission", True),
        ("production_certification", "certified"),
    ),
)
def test_boundary_flips_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError, match="external boundary"):
        replace(_package(), **{field: value})


def test_package_hash_tampering_is_rejected() -> None:
    result = _package()
    with pytest.raises(ValueError, match="package hash"):
        replace(
            result,
            application_package_sha256=_flip_first_nibble(
                result.application_package_sha256
            ),
        )


def test_module_has_no_io_network_or_subprocess_capability() -> None:
    tree = ast.parse(MODULE.read_text())
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imports.intersection(
        {
            "asyncio",
            "http",
            "io",
            "os",
            "pathlib",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
    )
    source = MODULE.read_text()
    for forbidden in ("open(", "subprocess", "http://", "https://"):
        assert forbidden not in source
