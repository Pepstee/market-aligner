from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import career_automation.candidate_release_gate as gate_module
import career_automation.candidate_release_authority as authority_module
from career_automation.browser_executor import ReleaseExecutionAuthority
from career_automation.candidate_release_authority import (
    CandidateReleaseExecutionAuthority,
)
from career_automation.application_quality_contracts import QualityReviewDisposition
from career_automation.application_sanity_review import (
    build_vacancy_review_material,
)
from career_automation.candidate_application_factory import (
    materialize_candidate_application_source,
)
from career_automation.candidate_release_gate import (
    CandidateAuthorityFiles,
    CandidateAuthorityReleaseGate,
    WorkableReleaseBinding,
    WorkableUploadBinding,
)
from career_automation.rendering import render_pdf_artifacts
from career_automation.evidence_matching import content_hash
from test_jaa08_independent_acceptance import _compilation_inputs
from test_candidate_application_factory import (
    AUTHORITY_PATH,
    DISCOVERY_PATH,
    _integrated_decision,
)


ROOT = Path(__file__).resolve().parent
NOW = datetime(2030, 1, 2, 12, tzinfo=timezone.utc)


def _workable_binding(**changes: object) -> WorkableReleaseBinding:
    values = {
        "tenant": "",
        "vacancy_id": "847CFBC5F4",
        "source_url": "https://apply.workable.com/j/847CFBC5F4",
        "application_url": "https://apply.workable.com/j/847CFBC5F4/apply/",
        "policy_sha256": "1" * 64,
        "package_sha256": "2" * 64,
        "answers_sha256": "3" * 64,
        "inventory_sha256": "4" * 64,
        "preflight_sha256": "5" * 64,
        "cv_pdf_sha256": "6" * 64,
        "cover_letter_pdf_sha256": "7" * 64,
        "cv_assurance_receipt_sha256": "8" * 64,
        "cover_letter_assurance_receipt_sha256": "9" * 64,
        "upload_bindings": (WorkableUploadBinding("resume", "cv", "6" * 64, "8" * 64),),
    }
    values.update(changes)
    return WorkableReleaseBinding(**values)


def test_workable_release_binding_accepts_exact_flat_cogna_shape() -> None:
    binding = _workable_binding()
    assert binding.document()["adapter_id"] == "workable.production"
    assert binding.document()["source_url"].endswith("/j/847CFBC5F4")


def test_workable_release_binding_accepts_exact_tenant_shape() -> None:
    binding = _workable_binding(
        tenant="cogna",
        source_url="https://apply.workable.com/cogna/j/847CFBC5F4",
        application_url="https://apply.workable.com/cogna/j/847CFBC5F4/apply/",
    )
    assert binding.tenant == "cogna"


def test_non_synthetic_workable_gate_requires_market_materialization_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _arguments, _url = _gate_inputs(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="requires market decision materialization"):
        CandidateAuthorityReleaseGate(
            tmp_path / "workable-gate.sqlite3",
            repository_root=gate.repository_root,
            authority_files=gate.authority_files,
            vacancy_requirements=gate.vacancy_requirements,
            workable_release_binding=_workable_binding(),
            clock=lambda: NOW,
        )

    synthetic_binding = _workable_binding(
        tenant="synthetic",
        source_url="https://apply.workable.com/synthetic/j/847CFBC5F4",
        application_url=("https://apply.workable.com/synthetic/j/847CFBC5F4/apply/"),
    )
    with pytest.raises(ValueError, match="requires market decision materialization"):
        CandidateAuthorityReleaseGate(
            tmp_path / "synthetic-non-loopback-gate.sqlite3",
            repository_root=gate.repository_root,
            authority_files=gate.authority_files,
            vacancy_requirements=gate.vacancy_requirements,
            workable_release_binding=synthetic_binding,
            clock=lambda: NOW,
        )


def test_candidate_execution_authority_requires_exact_workable_upload_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeGate:
        vacancy_requirements = ("requirement",)

    monkeypatch.setattr(authority_module, "CandidateAuthorityReleaseGate", FakeGate)
    monkeypatch.setattr(ReleaseExecutionAuthority, "__post_init__", lambda _self: None)
    monkeypatch.setattr(
        authority_module,
        "verify_ats_application_authority",
        lambda *_args, **_kwargs: None,
    )
    binding = _workable_binding()
    ats_authority = SimpleNamespace(
        document=lambda: {},
        inventory_sha256="a" * 64,
        answer_sha256="b" * 64,
    )
    quality_review = SimpleNamespace(
        disposition=QualityReviewDisposition.ACCEPTED,
        to_dict=lambda: {},
    )
    quality_input = SimpleNamespace(
        ats_application_authority=ats_authority,
        candidate_authority_sha256="c" * 64,
        publication_receipt=object(),
        editorial_skill_reviews=(),
    )
    monkeypatch.setattr(
        authority_module,
        "build_deterministic_preflight_quality_review",
        lambda _quality_input: quality_review,
    )
    selected = {
        "assurance.ats_application_authority": hashlib.sha256(b"{}\n").hexdigest(),
        "assurance.ats_inventory": ats_authority.inventory_sha256,
        "assurance.ats_answers": ats_authority.answer_sha256,
        "assurance.application_quality": hashlib.sha256(b"{}\n").hexdigest(),
    }
    monkeypatch.setattr(
        authority_module, "selected_archive_hashes", lambda *_args, **_kwargs: selected
    )
    raw_listing = b"vacancy"
    vacancy_sha256 = hashlib.sha256(raw_listing).hexdigest()
    vacancy_review_material = build_vacancy_review_material(
        raw_listing_bytes=raw_listing,
        visible_listing_text_bytes=b"Synthetic vacancy",
        expected_raw_listing_sha256=vacancy_sha256,
    )
    authority = object.__new__(CandidateReleaseExecutionAuthority)
    values = {
        "gate": FakeGate(),
        "vacancy_requirements": ("requirement",),
        "ats_provider": "workable",
        "ats_application_authority": ats_authority,
        "quality_input": quality_input,
        "quality_review": quality_review,
        "workable_release_binding": binding,
        "application_url": binding.application_url,
        "source": SimpleNamespace(vacancy_sha256=vacancy_sha256),
        "artifacts": SimpleNamespace(
            cv_pdf=SimpleNamespace(pdf_sha256=binding.cv_pdf_sha256),
            cover_letter_pdf=SimpleNamespace(
                pdf_sha256=binding.cover_letter_pdf_sha256
            ),
        ),
        "document_assurance_receipts": (
            SimpleNamespace(receipt_sha256=binding.cv_assurance_receipt_sha256),
            SimpleNamespace(
                receipt_sha256=binding.cover_letter_assurance_receipt_sha256
            ),
        ),
        "attached_roles": ("cv",),
        "upload_field_names": (("cv", "resume"),),
        "archive_receipt": object(),
        "archive_root": Path("/synthetic/archive"),
        "repository_root": Path("/synthetic/repository"),
        "vacancy_review_material": vacancy_review_material,
    }
    for name, value in values.items():
        object.__setattr__(authority, name, value)
    authority.__post_init__()

    object.__setattr__(authority, "upload_field_names", (("cv", "substituted"),))
    with pytest.raises(ValueError, match="execution binding is incomplete"):
        authority.__post_init__()

    object.__setattr__(authority, "upload_field_names", (("cv", "resume"),))
    object.__setattr__(authority, "attached_roles", ("cv", "cover_letter"))
    with pytest.raises(ValueError, match="execution binding is incomplete"):
        authority.__post_init__()


def test_candidate_gate_accepts_exact_cogna_market_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    market, inputs, projection = _integrated_decision(tmp_path)
    materialized = materialize_candidate_application_source(
        candidate_authority_path=AUTHORITY_PATH,
        deployment_binding=inputs["deployment_binding"],
        contact_authority=inputs["contact_authority"],
        decision_receipt=market.decision_receipt(),
        candidate_projection=projection,
        job_key=market.source_job_key,
        vacancy_sha256=market.raw_listing_sha256,
        source_url=market.source_url,
        role_title=market.role_title,
        company_name=market.company_name,
        contact=inputs["contact"],
        market_decision_authority=market,
    )
    authority_document = json.loads(AUTHORITY_PATH.read_bytes())
    monkeypatch.setattr(
        gate_module,
        "build_candidate_authority_document",
        lambda **_kwargs: authority_document,
    )
    monkeypatch.setattr(
        gate_module,
        "load_candidate_contact_authority",
        lambda *_args, **_kwargs: inputs["contact_authority"],
    )
    requirements = tuple(
        f"{row['requirement_id']}: {row['requirement_text']}"
        for row in market.evidence_matrix
    )
    files = CandidateAuthorityFiles(
        archive_root=AUTHORITY_PATH.parent.parent,
        discovery_path=DISCOVERY_PATH,
        candidate_authority_path=AUTHORITY_PATH,
        contact_authority_path=inputs["contact_authority"].source_path,
        job_key=market.source_job_key,
        decision_receipt_sha256=materialized.receipt.decision_receipt_sha256,
    )
    verified = gate_module._verify_durable_candidate_authority(
        files,
        repository_root=ROOT,
        vacancy_requirements=requirements,
        market_decision_authority=market,
        materialization_receipt=materialized.receipt,
        required_environment="synthetic",
    )
    assert verified["market_decision_authority_sha256"] == market.authority_sha256
    assert (
        verified["materialization_receipt_sha256"]
        == materialized.receipt.receipt_sha256
    )

    with pytest.raises(ValueError):
        replace(
            materialized.receipt,
            decision_authority_sha256="f" * 64,
            receipt_sha256="e" * 64,
        )

    forged_document = materialized.receipt.document(include_identity=False)
    forged_document["contact_envelope_sha256"] = "f" * 64
    forged = replace(
        materialized.receipt,
        contact_envelope_sha256="f" * 64,
        receipt_sha256=content_hash(forged_document),
    )
    with pytest.raises(ValueError, match="integrated market release authority differs"):
        gate_module._verify_durable_candidate_authority(
            files,
            repository_root=ROOT,
            vacancy_requirements=requirements,
            market_decision_authority=market,
            materialization_receipt=forged,
            required_environment="synthetic",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_url", "https://apply.workable.com/j/SUBSTITUTED"),
        ("application_url", "https://apply.workable.com/j/847CFBC5F4/apply/?x=1"),
        ("cv_pdf_sha256", "a" * 64),
        ("cover_letter_pdf_sha256", "b" * 64),
        ("inventory_sha256", "c" * 64),
        ("preflight_sha256", "d" * 64),
    ),
)
def test_workable_release_binding_changes_are_content_addressed(
    field: str, value: str
) -> None:
    original = _workable_binding()
    if field.endswith("url") or field == "cv_pdf_sha256":
        with pytest.raises(ValueError):
            _workable_binding(**{field: value})
    else:
        changed = _workable_binding(**{field: value})
        assert changed.document() != original.document()


def _gate_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    values = _compilation_inputs(tmp_path)
    _, _, contact, questions, source, artifacts, artifact_root, _ = values
    application_id = "1234567"
    application_url = f"https://job-boards.greenhouse.io/example/jobs/{application_id}"
    source = source.__class__(
        source.source_id,
        source.strategy_id,
        f"greenhouse:example:{application_id}",
        source.role_title,
        source.company_name,
        source.vacancy_source_identity,
        source.vacancy_sha256,
        source.contact,
        source.facts,
        source.style_slots,
        source.cv_sections,
        source.letter_sections,
        source.answers,
        source.content_sha256,
    )
    # Recompute the identity after replacing only the vacancy job key.
    body = source.document(include_identity=False)
    content_sha256 = hashlib.sha256(
        gate_module.canonical_json(body).encode()
    ).hexdigest()
    source = source.__class__(
        gate_module.content_hash(
            {
                "contract": "jaa07.application-source.v1",
                "strategy_id": source.strategy_id,
                "content_sha256": content_sha256,
            }
        ),
        source.strategy_id,
        source.job_key,
        source.role_title,
        source.company_name,
        source.vacancy_source_identity,
        source.vacancy_sha256,
        source.contact,
        source.facts,
        source.style_slots,
        source.cv_sections,
        source.letter_sections,
        source.answers,
        content_sha256,
    )
    artifacts = render_pdf_artifacts(source)
    artifact_root = tmp_path / "candidate-published"
    directory = artifact_root / artifacts.artifact_set_sha256
    directory.mkdir(parents=True)
    (directory / "cv.pdf").write_bytes(artifacts.cv_pdf.pdf_bytes)
    (directory / "cover-letter.pdf").write_bytes(artifacts.cover_letter_pdf.pdf_bytes)
    monkeypatch.setattr(gate_module, "exact_clean_head", lambda _root: "a" * 40)
    authority = {
        "job_key": source.job_key,
        "role_title": source.role_title,
        "company_name": source.company_name,
        "vacancy_sha256": source.vacancy_sha256,
        "source_url": application_url,
        "candidate_authority_sha256": "a" * 64,
        "candidate_decision_receipt_sha256": "b" * 64,
        "candidate_projection_sha256": "c" * 64,
        "duplicate_snapshot_sha256": "d" * 64,
        "contact_authority_sha256": contact.provenance_sha256,
        "contact_registry_sha256": "e" * 64,
    }
    authority_files = CandidateAuthorityFiles(
        archive_root=tmp_path,
        discovery_path=tmp_path / "discovery.json",
        candidate_authority_path=tmp_path / "authority.json",
        contact_authority_path=tmp_path / "contact.json",
        job_key=source.job_key,
        decision_receipt_sha256="b" * 64,
    )
    monkeypatch.setattr(
        gate_module,
        "_verify_durable_candidate_authority",
        lambda *_args, **_kwargs: dict(authority),
    )
    gate = CandidateAuthorityReleaseGate(
        tmp_path / "release.sqlite3",
        repository_root=ROOT,
        authority_files=authority_files,
        vacancy_requirements=("essential: approved requirement",),
        clock=lambda: NOW,
    )
    arguments = {
        "source": source,
        "artifacts": artifacts,
        "contact": contact,
        "questions": questions,
        "artifact_root": artifact_root,
        "repository_root": ROOT,
        "jurisdiction": "GB",
        "contract_type": "employee",
    }
    return gate, arguments, application_url


def test_candidate_gate_rejects_caller_minted_hash_mapping(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="durable authority files"):
        CandidateAuthorityReleaseGate(
            tmp_path / "release.sqlite3",
            repository_root=ROOT,
            authority_files={  # type: ignore[arg-type]
                "candidate_decision_receipt_sha256": "b" * 64,
                "duplicate_snapshot_sha256": "d" * 64,
            },
            vacancy_requirements=("essential: approved requirement",),
        )


def test_durable_authority_rehashes_exact_decision_projection_and_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_root = tmp_path / "archive"
    authority_root = archive_root / "candidate-authorities"
    object_root = archive_root / "objects"
    authority_root.mkdir(parents=True)
    duplicate_bytes = b"[]\n"
    duplicate_sha256 = hashlib.sha256(duplicate_bytes).hexdigest()
    duplicate_path = object_root / duplicate_sha256[:2] / duplicate_sha256
    duplicate_path.parent.mkdir(parents=True)
    duplicate_path.write_bytes(duplicate_bytes)
    projection_payload = {"schema_version": "jaa.candidate-authority-projection.v1"}
    projection_sha256 = hashlib.sha256(
        gate_module._json_bytes(projection_payload)
    ).hexdigest()
    projection = {**projection_payload, "projection_sha256": projection_sha256}
    receipt = {
        "decision": "eligible",
        "job_key": "greenhouse:example:1234567",
        "role_title": "Engineer",
        "company_name": "Example",
        "vacancy_sha256": "a" * 64,
        "source_url": "https://job-boards.greenhouse.io/example/jobs/1234567",
        "candidate_projection_sha256": projection_sha256,
        "duplicate_snapshot_sha256": duplicate_sha256,
        "evidence_matrix": [
            {
                "requirement_id": "R-001",
                "requirement_text": "approved requirement",
            }
        ],
    }
    receipt_sha256 = hashlib.sha256(gate_module._json_bytes(receipt)).hexdigest()
    document = {
        "schema_version": "jaa.production-candidate-authority.v2",
        "duplicate_snapshot_sha256": duplicate_sha256,
        "candidate_projection": projection,
        "decisions": [
            {
                "job_key": receipt["job_key"],
                "receipt": receipt,
                "receipt_sha256": receipt_sha256,
            }
        ],
    }
    authority_bytes = gate_module._json_bytes(document)
    authority_sha256 = hashlib.sha256(authority_bytes).hexdigest()
    authority_path = authority_root / f"{authority_sha256}.json"
    authority_path.write_bytes(authority_bytes)
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_text("{}\n", encoding="utf-8")
    contact_path = tmp_path / "contact.json"
    contact_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        gate_module,
        "build_candidate_authority_document",
        lambda **_kwargs: json.loads(authority_bytes),
    )
    monkeypatch.setattr(
        gate_module,
        "load_candidate_contact_authority",
        lambda *_args, **_kwargs: SimpleNamespace(
            authority_sha256="e" * 64,
            registry_sha256="f" * 64,
        ),
    )
    files = CandidateAuthorityFiles(
        archive_root=archive_root,
        discovery_path=discovery_path,
        candidate_authority_path=authority_path,
        contact_authority_path=contact_path,
        job_key=str(receipt["job_key"]),
        decision_receipt_sha256=receipt_sha256,
    )
    binding = gate_module._verify_durable_candidate_authority(
        files,
        repository_root=ROOT,
        vacancy_requirements=("R-001: approved requirement",),
    )
    assert binding["candidate_authority_sha256"] == authority_sha256
    assert binding["candidate_decision_receipt_sha256"] == receipt_sha256
    assert binding["contact_registry_sha256"] == "f" * 64
    forged = CandidateAuthorityFiles(
        **{
            **files.__dict__,
            "decision_receipt_sha256": "f" * 64,
        }
    )
    with pytest.raises(ValueError, match="durable authority binding differs"):
        gate_module._verify_durable_candidate_authority(
            forged,
            repository_root=ROOT,
            vacancy_requirements=("R-001: approved requirement",),
        )


def test_candidate_gate_issues_consumes_and_reverifies_exact_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    issued = gate.issue(**arguments, application_url=application_url)
    _row, manifest = gate._stored(issued.release_token)
    assert manifest["vacancy_requirements"] == ["essential: approved requirement"]
    gate.verify_token_official_route(
        release_token=issued.release_token,
        adapter_id="greenhouse.production",
        adapter_version="v1",
        source_identity=application_url,
    )
    gate.verify_current_release_token(
        release_token=issued.release_token,
        **arguments,
    )
    consumed = gate.consume_release_token(
        release_token=issued.release_token,
        consumed_at=NOW,
        **arguments,
    )
    verified = gate.verify_consumed_release_token(
        release_token=issued.release_token,
        consumed_at=NOW,
        **arguments,
    )
    assert verified == consumed
    with pytest.raises(ValueError, match="already consumed"):
        gate.consume_release_token(
            release_token=issued.release_token,
            consumed_at=NOW,
            **arguments,
        )


def test_unconsumed_preclick_release_is_superseded_with_append_only_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    first = gate.issue(**arguments, application_url=application_url)
    gate._clock = lambda: NOW + timedelta(days=1)
    second = gate.issue(**arguments, application_url=application_url)
    assert second.release_token != first.release_token

    with sqlite3.connect(gate.path) as connection:
        superseded = connection.execute(
            """SELECT manifest_sha256,replacement_manifest_sha256
               FROM candidate_authority_release_token_supersessions"""
        ).fetchone()
        active = connection.execute(
            "SELECT manifest_sha256,consumed_at FROM candidate_authority_release_tokens"
        ).fetchone()
    assert superseded == (first.manifest_sha256, second.manifest_sha256)
    assert active == (second.manifest_sha256, None)
    with pytest.raises(ValueError, match="unknown"):
        gate._stored(first.release_token)
    gate._stored(second.release_token)


def test_consumed_release_cannot_be_superseded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    issued = gate.issue(**arguments, application_url=application_url)
    gate.consume_release_token(
        release_token=issued.release_token,
        consumed_at=NOW,
        **arguments,
    )
    gate._clock = lambda: NOW + timedelta(days=1)
    with pytest.raises(ValueError, match="duplicate authority differs"):
        gate.issue(**arguments, application_url=application_url)


def test_candidate_gate_rejects_pdf_or_repository_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    issued = gate.issue(**arguments, application_url=application_url)
    artifacts = arguments["artifacts"]
    directory = arguments["artifact_root"] / artifacts.artifact_set_sha256
    (directory / "cv.pdf").write_bytes(b"different")
    with pytest.raises(ValueError, match="upload file differs"):
        gate.consume_release_token(
            release_token=issued.release_token,
            consumed_at=NOW,
            **arguments,
        )

    (directory / "cv.pdf").write_bytes(artifacts.cv_pdf.pdf_bytes)
    monkeypatch.setattr(gate_module, "exact_clean_head", lambda _root: "f" * 40)
    with pytest.raises(ValueError, match="authority drift"):
        gate.consume_release_token(
            release_token=issued.release_token,
            consumed_at=NOW,
            **arguments,
        )


def test_candidate_gate_rejects_route_or_candidate_binding_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    issued = gate.issue(**arguments, application_url=application_url)
    with pytest.raises(ValueError, match="different official route"):
        gate.verify_token_official_route(
            release_token=issued.release_token,
            adapter_id="greenhouse.production",
            adapter_version="v1",
            source_identity=application_url.replace("1234567", "7654321"),
        )
    changed = dict(arguments)
    changed["jurisdiction"] = "US"
    with pytest.raises(ValueError, match="work-right scope"):
        gate.consume_release_token(
            release_token=issued.release_token,
            consumed_at=NOW,
            **changed,
        )


def test_candidate_gate_rejects_vacancy_requirement_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    issued = gate.issue(**arguments, application_url=application_url)
    gate.vacancy_requirements = ("essential: substituted requirement",)
    with pytest.raises(ValueError, match="authority drift"):
        gate.consume_release_token(
            release_token=issued.release_token,
            consumed_at=NOW,
            **arguments,
        )


def test_candidate_gate_reauthenticates_durable_sources_before_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate, arguments, application_url = _gate_inputs(tmp_path, monkeypatch)
    issued = gate.issue(**arguments, application_url=application_url)
    monkeypatch.setattr(
        gate_module,
        "_verify_durable_candidate_authority",
        lambda *_args, **_kwargs: {
            **gate.authority_binding,
            "candidate_decision_receipt_sha256": "f" * 64,
        },
    )
    with pytest.raises(ValueError, match="durable authority drifted"):
        gate.consume_release_token(
            release_token=issued.release_token,
            consumed_at=NOW,
            **arguments,
        )
