"""Deterministic editable-text rendering for JAA-07 application sources."""

from __future__ import annotations

import hashlib
import io
import re
import textwrap
from dataclasses import dataclass
from typing import Iterable

from .application_compiler import (
    FACT_TOKEN,
    ApplicationSource,
    verify_application_source,
)


PDF_FORBIDDEN = (
    b"/Image",
    b"/XObject",
    b"/Annots",
    b"/AcroForm",
    b"/OCProperties",
    b"/ExtGState",
    b"/Pattern",
    b"/Shading",
    b"/Artifact",
    b" 3 Tr",
)
PDF_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_LINES_PER_PAGE = 54
MAX_LINE_CHARACTERS = 88


@dataclass(frozen=True)
class EditableArtifacts:
    cv_text: str
    cover_letter_text: str
    answers_text: str
    cv_sha256: str
    cover_letter_sha256: str
    answers_sha256: str


@dataclass(frozen=True)
class PdfArtifact:
    document_kind: str
    pdf_bytes: bytes
    pdf_sha256: str
    extracted_text: str
    extracted_text_sha256: str
    page_count: int
    rendered_lines: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        if self.document_kind not in {"cv", "cover_letter"}:
            raise ValueError("PDF artifact document kind is unsupported")
        if not self.pdf_bytes.startswith(b"%PDF-1.4\n"):
            raise ValueError("PDF artifact has an invalid signature")
        if (
            not PDF_DIGEST.fullmatch(self.pdf_sha256)
            or not PDF_DIGEST.fullmatch(self.extracted_text_sha256)
        ):
            raise ValueError("PDF artifact hashes must be lowercase SHA-256")
        if self.page_count != len(self.rendered_lines) or self.page_count < 1:
            raise ValueError("PDF artifact page identity is inconsistent")


@dataclass(frozen=True)
class ApplicationArtifacts:
    source_id: str
    editable: EditableArtifacts
    cv_pdf: PdfArtifact
    cover_letter_pdf: PdfArtifact
    artifact_set_sha256: str
    certifies_slice: bool = False

    def __post_init__(self) -> None:
        if not PDF_DIGEST.fullmatch(self.source_id):
            raise ValueError("artifact source ID must be a lowercase SHA-256")
        if not PDF_DIGEST.fullmatch(self.artifact_set_sha256):
            raise ValueError("artifact-set hash must be a lowercase SHA-256")
        if self.certifies_slice is not False:
            raise ValueError("offline rendered artifacts cannot certify JAA-07")


def _join_section(
    source: ApplicationSource,
    heading: str,
    sentence_ids: tuple[str, ...],
    style_slot_ids: tuple[str, ...],
) -> str:
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    values = [heading]
    values.extend(slots[slot_id] for slot_id in style_slot_ids)
    values.extend(facts[sentence_id] for sentence_id in sentence_ids)
    return "\n".join(values)


def render_editable_text(source: ApplicationSource) -> EditableArtifacts:
    """Render plain, single-column editable sources with stable ordering."""
    verify_application_source(source)
    contact = source.contact
    cv_header = "\n".join(
        (contact.full_name, contact.email, contact.phone, contact.city)
    )
    cv = "\n\n".join(
        (
            cv_header,
            *(
                _join_section(
                    source,
                    section.heading,
                    section.sentence_ids,
                    section.style_slot_ids,
                )
                for section in source.cv_sections
            ),
        )
    ) + "\n"
    letter_header = "\n".join(
        (
            contact.full_name,
            contact.email,
            contact.phone,
            contact.city,
            source.role_title,
            source.company_name,
        )
    )
    letter = "\n\n".join(
        (
            letter_header,
            *(
                _join_section(
                    source,
                    section.heading,
                    section.sentence_ids,
                    section.style_slot_ids,
                )
                for section in source.letter_sections
            ),
        )
    ) + "\n"
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    answers = "\n\n".join(
        "\n".join(
            (
                answer.question,
                *(slots[value] for value in answer.style_slot_ids),
                *(facts[value] for value in answer.sentence_ids),
            )
        )
        for answer in source.answers
    )
    if answers:
        answers += "\n"
    return EditableArtifacts(
        cv,
        letter,
        answers,
        hashlib.sha256(cv.encode()).hexdigest(),
        hashlib.sha256(letter.encode()).hexdigest(),
        hashlib.sha256(answers.encode()).hexdigest(),
    )


def _wrapped_lines(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if any(ord(character) < 32 and character != "\t" for character in value):
            raise ValueError("PDF input contains control characters")
        for line in value.expandtabs(4).splitlines():
            clean = line.strip()
            if not clean:
                continue
            wrapped = textwrap.wrap(
                clean,
                width=MAX_LINE_CHARACTERS,
                break_long_words=False,
                break_on_hyphens=False,
                replace_whitespace=True,
                drop_whitespace=True,
            )
            if not wrapped or any(len(item) > MAX_LINE_CHARACTERS for item in wrapped):
                raise ValueError("PDF input contains an unrenderable long token")
            result.extend(wrapped)
    if not result:
        raise ValueError("PDF page cannot be empty")
    if len(result) > MAX_LINES_PER_PAGE:
        raise ValueError("document content exceeds its deterministic page budget")
    return tuple(result)


def _pdf_escape(value: str) -> bytes:
    try:
        raw = value.encode("cp1252")
    except UnicodeEncodeError as exc:
        raise ValueError("PDF text contains characters outside the ATS font encoding") from exc
    return (
        raw.replace(b"\\", b"\\\\")
        .replace(b"(", b"\\(")
        .replace(b")", b"\\)")
    )


def _content_stream(lines: tuple[str, ...]) -> bytes:
    commands = [b"BT", b"/F1 10 Tf", b"50 792 Td", b"13 TL"]
    for index, line in enumerate(lines):
        if index:
            commands.append(b"T*")
        commands.append(b"(" + _pdf_escape(line) + b") Tj")
    commands.append(b"ET")
    return b"\n".join(commands) + b"\n"


def _build_text_pdf(pages: tuple[tuple[str, ...], ...]) -> bytes:
    """Build the smallest deterministic PDF subset needed for ATS text."""
    if not pages:
        raise ValueError("PDF requires at least one page")
    # 1 catalog, 2 page tree, then page/content pairs, then one Type1 font.
    font_id = 3 + (2 * len(pages))
    page_ids = tuple(3 + (index * 2) for index in range(len(pages)))
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: (
            b"<< /Type /Pages /Kids ["
            + b" ".join(f"{value} 0 R".encode() for value in page_ids)
            + f"] /Count {len(pages)} >>".encode()
        ),
        font_id: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    }
    for index, lines in enumerate(pages):
        page_id = page_ids[index]
        content_id = page_id + 1
        stream = _content_stream(lines)
        objects[page_id] = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            + f"/Resources << /Font << /F1 {font_id} 0 R >> >> ".encode()
            + f"/Contents {content_id} 0 R >>".encode()
        )
        objects[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream
            + b"endstream"
        )
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (font_id + 1)
    for object_id in range(1, font_id + 1):
        offsets[object_id] = len(output)
        output.extend(f"{object_id} 0 obj\n".encode())
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {font_id + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        (
            f"trailer\n<< /Size {font_id + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode()
    )
    return bytes(output)


def _extract_pdf_text(pdf_bytes: bytes) -> tuple[str, int]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - packaging contract
        raise RuntimeError("the pinned pypdf runtime is required") from exc
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)
        text = "\n".join((page.extract_text() or "").rstrip() for page in reader.pages)
    except Exception as exc:
        raise ValueError("PDF artifact cannot be parsed independently") from exc
    return text + ("\n" if text else ""), len(reader.pages)


def _normalized_lines(text: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in text.splitlines() if line.strip())


def validate_pdf_artifact(
    artifact: PdfArtifact,
    *,
    expected_page_count: int,
    required_values: Iterable[str],
) -> None:
    if any(marker in artifact.pdf_bytes for marker in PDF_FORBIDDEN):
        raise ValueError("PDF contains a forbidden rich, hidden or interactive feature")
    if artifact.pdf_bytes != _build_text_pdf(artifact.rendered_lines):
        raise ValueError("PDF differs from the deterministic text-only subset")
    if hashlib.sha256(artifact.pdf_bytes).hexdigest() != artifact.pdf_sha256:
        raise ValueError("PDF bytes do not match their content hash")
    extracted, pages = _extract_pdf_text(artifact.pdf_bytes)
    if pages != expected_page_count or artifact.page_count != expected_page_count:
        raise ValueError("PDF page count differs from the document contract")
    if (
        extracted != artifact.extracted_text
        or hashlib.sha256(extracted.encode()).hexdigest()
        != artifact.extracted_text_sha256
    ):
        raise ValueError("PDF extracted text differs from its retained artifact")
    expected_lines = tuple(
        line for page in artifact.rendered_lines for line in page
    )
    if _normalized_lines(extracted) != expected_lines:
        raise ValueError("PDF parser output differs from the deterministic source lines")
    normalized = " ".join(_normalized_lines(extracted))
    for value in required_values:
        if " ".join(value.split()) not in normalized:
            raise ValueError("PDF parser output lost an authoritative value")


def _artifact(document_kind: str, pages: tuple[tuple[str, ...], ...]) -> PdfArtifact:
    pdf = _build_text_pdf(pages)
    extracted, page_count = _extract_pdf_text(pdf)
    return PdfArtifact(
        document_kind,
        pdf,
        hashlib.sha256(pdf).hexdigest(),
        extracted,
        hashlib.sha256(extracted.encode()).hexdigest(),
        page_count,
        pages,
    )


def render_pdf_artifacts(source: ApplicationSource) -> ApplicationArtifacts:
    """Render and independently parse exact two-page CV / one-page letter PDFs."""
    verify_application_source(source)
    editable = render_editable_text(source)
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    contact_values = (
        source.contact.full_name,
        source.contact.email,
        source.contact.phone,
        source.contact.city,
    )

    def section_values(indexes: tuple[int, ...]) -> tuple[str, ...]:
        values: list[str] = []
        for index in indexes:
            section = source.cv_sections[index]
            values.append(section.heading)
            values.extend(slots[value] for value in section.style_slot_ids)
            values.extend(facts[value] for value in section.sentence_ids)
        return tuple(values)

    cv_pages = (
        _wrapped_lines((*contact_values, *section_values((0, 1)))),
        _wrapped_lines(section_values((2, 3))),
    )
    letter_values: list[str] = [
        *contact_values,
        source.role_title,
        source.company_name,
    ]
    for section in source.letter_sections:
        letter_values.append(section.heading)
        letter_values.extend(slots[value] for value in section.style_slot_ids)
        letter_values.extend(facts[value] for value in section.sentence_ids)
    letter_pages = (_wrapped_lines(letter_values),)
    cv_pdf = _artifact("cv", cv_pages)
    letter_pdf = _artifact("cover_letter", letter_pages)
    required_cv = (
        *contact_values,
        *(row.text for row in source.facts if row.document_kind == "cv"),
    )
    required_letter = (
        *contact_values,
        source.role_title,
        source.company_name,
        *(row.text for row in source.facts if row.document_kind == "cover_letter"),
    )
    validate_pdf_artifact(cv_pdf, expected_page_count=2, required_values=required_cv)
    validate_pdf_artifact(
        letter_pdf,
        expected_page_count=1,
        required_values=required_letter,
    )
    extracted_tokens = set(FACT_TOKEN.findall(
        f"{cv_pdf.extracted_text}\n{letter_pdf.extracted_text}"
    ))
    source_tokens = set(FACT_TOKEN.findall(
        f"{editable.cv_text}\n{editable.cover_letter_text}"
    ))
    if extracted_tokens != source_tokens:
        raise ValueError("PDF rendering changed dates, metrics or contact tokens")
    artifact_set_sha256 = hashlib.sha256(
        "\n".join(
            (
                source.source_id,
                editable.cv_sha256,
                editable.cover_letter_sha256,
                editable.answers_sha256,
                cv_pdf.pdf_sha256,
                cv_pdf.extracted_text_sha256,
                letter_pdf.pdf_sha256,
                letter_pdf.extracted_text_sha256,
            )
        ).encode()
    ).hexdigest()
    return ApplicationArtifacts(
        source.source_id,
        editable,
        cv_pdf,
        letter_pdf,
        artifact_set_sha256,
    )
