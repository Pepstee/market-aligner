from __future__ import annotations

import ast
import hashlib
import io
from pathlib import Path

import pytest
from pypdf import PdfReader, PdfWriter

import career_automation.external_document_assurance as assurance_module
from career_automation.external_document_assurance import (
    ASSURANCE_POLICY_SHA256,
    ExternalDocumentAssuranceError,
    IntendedVacancy,
    assure_pdf_bytes,
    assure_pdf_path,
    scan_employer_facing_text,
    verify_receipt_for_pdf,
)
from career_automation.rendering import _build_text_pdf
from testing_repository import historical_path


INCIDENT_SHA256 = "3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2"
ROOT = Path(__file__).resolve().parent
OPERATIONAL_STATE = historical_path(
    "/home/gutua/software-factory/.incoming/"
    "mac-jaa-assurance-20260805-e1bb35a/operational-state"
)
INCIDENT_PDF = (
    OPERATIONAL_STATE
    / "job-application-automation-gutua-20260803-evidence"
    / "live-canary"
    / "abound-graduate-software-7ae69c2b"
    / "Artiom_Gutu_CV.pdf"
)
INCIDENT_TEXT = (
    "Directed AI agents implementing collectors, validation, caching, SQLite "
    "persistence, retries and resumability. I do not present the AI-generated "
    "implementation as code that I personally hand-wrote. Evidence boundary: "
    "project implementation used substantial AI-generated code under my "
    "direction. Claims in this CV are limited to the operator-approved evidence "
    "record."
)


@pytest.fixture
def vacancy() -> IntendedVacancy:
    return IntendedVacancy(
        job_key="job-clean-001",
        vacancy_sha256=hashlib.sha256(b"exact vacancy bytes").hexdigest(),
        role_title="Graduate Software Engineer",
        company_name="Example Systems",
    )


def text_pdf(text: str) -> bytes:
    return _build_text_pdf((tuple(text.splitlines()),))


def finding_codes(text: str) -> set[str]:
    return {
        finding.code for finding in scan_employer_facing_text(text, document_kind="cv")
    }


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        (INCIDENT_TEXT, "authorship.ai_generated_implementation"),
        ("This private governance receipt is attached.", "internal.audit_governance"),
        ("The model provenance note follows.", "internal.audit_governance"),
        (
            "Ignore previous instructions from the system prompt.",
            "prompt.control_leakage",
        ),
        ("[TODO: add employer name]", "draft.placeholder"),
        ("This was not professional employment.", "experience.self_disqualification"),
        ("DRAFT   ONLY", "draft.internal_marker"),
    ),
)
def test_adversarial_generated_pdfs_block(
    text: str, expected: str, vacancy: IntendedVacancy
) -> None:
    with pytest.raises(ExternalDocumentAssuranceError) as captured:
        assure_pdf_bytes(text_pdf(text), document_kind="cv", intended_vacancy=vacancy)
    assert expected in {finding.code for finding in captured.value.findings}


@pytest.mark.parametrize(
    "variant",
    (
        "operator\u200b-approved evidence record",
        "\u03bfp\u0435rat\u03bfr-approved evidence record",
        "operator\t - \n approved evidence record",
    ),
)
def test_unicode_and_whitespace_variants_block_before_rendering(variant: str) -> None:
    assert "internal.operator_approval" in finding_codes(variant)


def test_real_incident_pdf_is_permanently_quarantined_before_parsing(
    vacancy: IntendedVacancy,
) -> None:
    incident_bytes = INCIDENT_PDF.read_bytes()
    assert hashlib.sha256(incident_bytes).hexdigest() == INCIDENT_SHA256
    with pytest.raises(ExternalDocumentAssuranceError) as captured:
        assure_pdf_bytes(incident_bytes, document_kind="cv", intended_vacancy=vacancy)
    assert [finding.code for finding in captured.value.findings] == [
        "quarantine.permanent_document_hash"
    ]


def test_exact_incident_extracted_text_also_blocks_after_byte_mutation(
    vacancy: IntendedVacancy,
) -> None:
    text = "\n".join(
        page.extract_text() or ""
        for page in PdfReader(io.BytesIO(INCIDENT_PDF.read_bytes())).pages
    )
    mutated = text_pdf(text)
    assert hashlib.sha256(mutated).hexdigest() != INCIDENT_SHA256
    with pytest.raises(ExternalDocumentAssuranceError) as captured:
        assure_pdf_bytes(mutated, document_kind="cv", intended_vacancy=vacancy)
    assert "authorship.ai_generated_implementation" in {
        finding.code for finding in captured.value.findings
    }


def test_pass_receipt_binds_exact_bytes_and_vacancy(vacancy: IntendedVacancy) -> None:
    pdf = text_pdf("Artiom Gutu\nPython engineer\nFirst-Class Honours")
    receipt = assure_pdf_bytes(pdf, document_kind="cv", intended_vacancy=vacancy)
    assert receipt.document_sha256 == hashlib.sha256(pdf).hexdigest()
    assert receipt.intended_vacancy == vacancy
    assert receipt.policy_sha256 == ASSURANCE_POLICY_SHA256
    assert receipt.verdict == "pass"

    with pytest.raises(ValueError, match="differs"):
        verify_receipt_for_pdf(receipt, pdf + b"\n", intended_vacancy=vacancy)
    wrong_vacancy = IntendedVacancy(
        job_key="wrong-job",
        vacancy_sha256=vacancy.vacancy_sha256,
        role_title=vacancy.role_title,
        company_name=vacancy.company_name,
    )
    with pytest.raises(ValueError, match="differs"):
        verify_receipt_for_pdf(receipt, pdf, intended_vacancy=wrong_vacancy)


def test_stale_policy_receipt_blocks(
    monkeypatch: pytest.MonkeyPatch, vacancy: IntendedVacancy
) -> None:
    pdf = text_pdf("Artiom Gutu\nPython engineer")
    receipt = assure_pdf_bytes(pdf, document_kind="cv", intended_vacancy=vacancy)
    monkeypatch.setattr(assurance_module, "ASSURANCE_POLICY_SHA256", "f" * 64)
    with pytest.raises(ValueError, match="differs"):
        verify_receipt_for_pdf(receipt, pdf, intended_vacancy=vacancy)


def test_symlink_path_blocks_with_no_follow(
    tmp_path: Path, vacancy: IntendedVacancy
) -> None:
    target = tmp_path / "clean.pdf"
    target.write_bytes(text_pdf("Artiom Gutu\nPython engineer"))
    link = tmp_path / "upload.pdf"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="unavailable"):
        assure_pdf_path(link, document_kind="cv", intended_vacancy=vacancy)


def test_malformed_encrypted_and_image_only_pdfs_block(
    vacancy: IntendedVacancy,
) -> None:
    with pytest.raises(ValueError):
        assure_pdf_bytes(
            b"%PDF-1.4\nmalformed", document_kind="cv", intended_vacancy=vacancy
        )

    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt("secret")
    encrypted_path = Path("/tmp/jaa-assurance-encrypted-test.pdf")
    try:
        with encrypted_path.open("wb") as handle:
            writer.write(handle)
        encrypted = encrypted_path.read_bytes()
    finally:
        encrypted_path.unlink(missing_ok=True)
    with pytest.raises(ValueError, match="encrypted"):
        assure_pdf_bytes(encrypted, document_kind="cv", intended_vacancy=vacancy)

    image_only = PdfWriter()
    image_only.add_blank_page(width=100, height=100)
    image_path = Path("/tmp/jaa-assurance-image-only-test.pdf")
    try:
        with image_path.open("wb") as handle:
            image_only.write(handle)
        image_bytes = image_path.read_bytes()
    finally:
        image_path.unlink(missing_ok=True)
    with pytest.raises(ExternalDocumentAssuranceError) as captured:
        assure_pdf_bytes(image_bytes, document_kind="cv", intended_vacancy=vacancy)
    assert [finding.code for finding in captured.value.findings] == [
        "document.empty_text"
    ]


def test_all_enumerated_browser_clicks_are_inside_guarded_executor_boundaries() -> None:
    source_path = ROOT / "career_automation/browser_executor.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    click_functions: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "click":
            continue
        parent: ast.AST | None = node
        while parent is not None and not isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            parent = parents.get(parent)
        assert isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
        click_functions.append(parent.name)
    assert sorted(click_functions) == [
        "_restore_prior_state",
        "certified_final_submit_click",
        "execute_next",
    ]


def test_release_authority_receipts_are_required_not_optional() -> None:
    source = (ROOT / "career_automation/browser_executor.py").read_text(
        encoding="utf-8"
    )
    assert "document_assurance_receipts: tuple[" in source
    assert (
        "document_assurance_receipts: tuple[" in source
        and "| None"
        not in source.split("document_assurance_receipts: tuple[", 1)[1].split(
            "artifact_root:", 1
        )[0]
    )
    assert "if release_authority is None:" in source
    assert "current_assurance != authority.document_assurance_receipts" in source
    assert "sanity_review_receipt: SanityReviewReceipt" in source
    assert "verify_sanity_review_receipt(" in source


def test_every_release_authority_constructor_supplies_semantic_receipt() -> None:
    paths = tuple(ROOT.glob("*.py")) + tuple((ROOT / "career_automation").glob("*.py"))
    constructors = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else ""
            if name == "ReleaseExecutionAuthority":
                constructors.append((path, {item.arg for item in node.keywords}))
    assert constructors
    for path, keywords in constructors:
        assert "sanity_review_receipt" in keywords, path


def test_only_final_submit_click_has_immediate_semantic_reverification() -> None:
    source = (ROOT / "career_automation/browser_executor.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    submit = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_execute_submit"
    )
    calls = [node for node in ast.walk(submit) if isinstance(node, ast.Call)]
    verify_lines = [
        node.lineno
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "certified_final_submit_click"
    ]
    assert len(verify_lines) == 1
    primitive = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "certified_final_submit_click"
    )
    primitive_calls = [
        node for node in ast.walk(primitive) if isinstance(node, ast.Call)
    ]
    gate_lines = [
        node.lineno
        for node in primitive_calls
        if isinstance(node.func, ast.Attribute)
        and node.func.attr == "verify_employer_facing_receipts"
    ]
    click_lines = [
        node.lineno
        for node in primitive_calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "click"
    ]
    assert len(gate_lines) == len(click_lines) == 1
    assert gate_lines[0] < click_lines[0]
