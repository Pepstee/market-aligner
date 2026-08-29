"""Deterministic ATS-safe UK application rendering with proved geometry."""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from .application_compiler import (
    FACT_TOKEN,
    ApplicationSource,
    verify_application_source,
)
from .evidence_matching import content_hash
from .external_document_assurance import (
    IntendedVacancy,
    assert_application_artifacts,
    assert_employer_facing_text,
    inspect_pdf_bytes,
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
CV_SECTION_HEADINGS = frozenset(
    {
        "Professional Summary",
        "Core Capabilities",
        "Projects",
        "Education",
        "Experience",
        "Skills",
    }
)

PAGE_WIDTH = 595.0
PAGE_HEIGHT = 842.0
LEFT_MARGIN = 50.0
RIGHT_MARGIN = 50.0
TOP_BASELINE = 795.0
BOTTOM_MARGIN = 47.0
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN

RENDERER_POLICY = {
    "schema_version": "jaa.ats-pdf-renderer-policy.v4",
    "page": {"width": PAGE_WIDTH, "height": PAGE_HEIGHT},
    "margins": {
        "left": LEFT_MARGIN,
        "right": RIGHT_MARGIN,
        "top_baseline": TOP_BASELINE,
        "bottom": BOTTOM_MARGIN,
    },
    "fonts": ["Helvetica", "Helvetica-Bold"],
    "layout": "single-column-point-width-v1",
    "width_metrics": "helvetica-afm-plus-conservative-bold-v1",
    "styles": {
        "name": {"font": "Helvetica-Bold", "size": 16.0},
        "role": {"font": "Helvetica", "size": 10.0},
        "contact": {"font": "Helvetica", "size": 10.0},
        "heading": {"font": "Helvetica-Bold", "size": 11.0},
        "body": {"font": "Helvetica", "size": 10.0},
    },
    "answers": "immutable-application-source-ordered-utf8-display-v1",
    "cv_pages": [1, 2],
    "cover_letter_pages": [1],
}
RENDERER_POLICY_SHA256 = content_hash(RENDERER_POLICY)

# Standard Helvetica AFM widths in thousandths of an em. Unknown WinAnsi glyphs
# conservatively use 1000, which may over-wrap but cannot claim a clipped line.
_WIDTHS: dict[str, int] = {
    " ": 278,
    "!": 278,
    '"': 355,
    "#": 556,
    "$": 556,
    "%": 889,
    "&": 667,
    "'": 191,
    "(": 333,
    ")": 333,
    "*": 389,
    "+": 584,
    ",": 278,
    "-": 333,
    ".": 278,
    "/": 278,
    ":": 278,
    ";": 278,
    "<": 584,
    "=": 584,
    ">": 584,
    "?": 556,
    "@": 1015,
    "[": 278,
    "\\": 278,
    "]": 278,
    "^": 469,
    "_": 556,
    "`": 333,
    "{": 334,
    "|": 260,
    "}": 334,
    "~": 584,
}
_WIDTHS.update({str(value): 556 for value in range(10)})
_WIDTHS.update(
    dict(
        zip(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            (
                667,
                667,
                722,
                722,
                667,
                611,
                778,
                722,
                278,
                500,
                667,
                556,
                833,
                722,
                778,
                667,
                778,
                722,
                667,
                611,
                722,
                667,
                944,
                667,
                667,
                611,
            ),
            strict=True,
        )
    )
)

# Helvetica-Bold differs materially from regular Helvetica.  Known AFM letter
# widths are exact; every other WinAnsi glyph uses a conservative 12% expansion
# so geometry validation can over-wrap but never understate a bold line.
_BOLD_WIDTHS = {
    character: min(1000, ((width * 112) + 99) // 100)
    for character, width in _WIDTHS.items()
}
_BOLD_WIDTHS.update(
    dict(
        zip(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            (
                722,
                722,
                722,
                722,
                667,
                611,
                778,
                722,
                278,
                556,
                722,
                611,
                833,
                722,
                778,
                667,
                778,
                722,
                667,
                611,
                722,
                722,
                944,
                722,
                722,
                611,
            ),
            strict=True,
        )
    )
)
_BOLD_WIDTHS.update(
    dict(
        zip(
            "abcdefghijklmnopqrstuvwxyz",
            (
                556,
                611,
                556,
                611,
                556,
                333,
                611,
                611,
                278,
                278,
                556,
                278,
                889,
                611,
                611,
                611,
                611,
                389,
                556,
                333,
                611,
                556,
                778,
                556,
                556,
                500,
            ),
            strict=True,
        )
    )
)
_WIDTHS.update(
    dict(
        zip(
            "abcdefghijklmnopqrstuvwxyz",
            (
                556,
                556,
                500,
                556,
                556,
                278,
                556,
                556,
                222,
                222,
                500,
                222,
                833,
                556,
                556,
                556,
                556,
                333,
                500,
                278,
                556,
                500,
                722,
                500,
                500,
                500,
            ),
            strict=True,
        )
    )
)


@dataclass(frozen=True)
class EditableArtifacts:
    cv_text: str
    cover_letter_text: str
    answers_text: str
    cv_sha256: str
    cover_letter_sha256: str
    answers_sha256: str
    @property
    def form_answers_bytes(self) -> bytes:
        """Exact canonical answer bytes owned by the current source renderer."""

        return self.answers_text.encode("utf-8")

    @property
    def answers_display_text(self) -> str:
        """Compatibility view consumed by form fillers and operator previews."""

        return self.answers_text


@dataclass(frozen=True)
class PdfLineBox:
    text: str
    x: float
    baseline_y: float
    width: float
    font_size: float
    font_name: str
    role: str
    color: tuple[float, float, float]

    @property
    def top(self) -> float:
        return self.baseline_y + (self.font_size * 0.82)

    @property
    def bottom(self) -> float:
        return self.baseline_y - (self.font_size * 0.22)

    def __post_init__(self) -> None:
        if not self.text or self.font_name not in {"Helvetica", "Helvetica-Bold"}:
            raise ValueError("PDF line box is malformed")
        if self.width < 0.0 or self.font_size <= 0.0:
            raise ValueError("PDF line geometry is invalid")


@dataclass(frozen=True)
class PdfArtifact:
    document_kind: str
    pdf_bytes: bytes
    pdf_sha256: str
    extracted_text: str
    extracted_text_sha256: str
    page_count: int
    rendered_lines: tuple[tuple[str, ...], ...]
    layout_boxes: tuple[tuple[PdfLineBox, ...], ...] = ()
    renderer_policy_sha256: str = RENDERER_POLICY_SHA256

    def __post_init__(self) -> None:
        if self.document_kind not in {"cv", "cover_letter"}:
            raise ValueError("PDF artifact document kind is unsupported")
        if not self.pdf_bytes.startswith(b"%PDF-1.4\n"):
            raise ValueError("PDF artifact has an invalid signature")
        if not PDF_DIGEST.fullmatch(self.pdf_sha256) or not PDF_DIGEST.fullmatch(
            self.extracted_text_sha256
        ):
            raise ValueError("PDF artifact hashes must be lowercase SHA-256")
        if self.page_count != len(self.rendered_lines) or self.page_count < 1:
            raise ValueError("PDF artifact page identity is inconsistent")
        if self.layout_boxes and len(self.layout_boxes) != self.page_count:
            raise ValueError("PDF layout page identity is inconsistent")
        if self.renderer_policy_sha256 != RENDERER_POLICY_SHA256:
            raise ValueError("PDF renderer policy is stale")


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


@dataclass(frozen=True)
class _TextStyle:
    font_name: str
    font_size: float
    leading: float
    color: tuple[float, float, float]


@dataclass(frozen=True)
class _LineSpec:
    text: str
    role: str
    style: _TextStyle
    spacing_before: float = 0.0
    spacing_after: float = 0.0
    indent: float = 0.0


_NAME = _TextStyle("Helvetica-Bold", 16.0, 20.0, (0.10, 0.18, 0.28))
_ROLE = _TextStyle("Helvetica", 10.0, 14.0, (0.23, 0.29, 0.36))
_CONTACT = _TextStyle("Helvetica", 10.0, 13.0, (0.30, 0.34, 0.39))
_HEADING = _TextStyle("Helvetica-Bold", 11.0, 16.0, (0.10, 0.18, 0.28))
_BODY = _TextStyle("Helvetica", 10.0, 13.5, (0.10, 0.12, 0.15))
_BULLET = _TextStyle("Helvetica", 10.0, 13.5, (0.10, 0.12, 0.15))
_SPACIOUS_NAME = _TextStyle("Helvetica-Bold", 16.0, 22.0, (0.10, 0.18, 0.28))
_SPACIOUS_ROLE = _TextStyle("Helvetica", 10.0, 15.0, (0.23, 0.29, 0.36))
_SPACIOUS_CONTACT = _TextStyle("Helvetica", 10.0, 14.0, (0.30, 0.34, 0.39))
_SPACIOUS_HEADING = _TextStyle("Helvetica-Bold", 11.0, 18.0, (0.10, 0.18, 0.28))
_SPACIOUS_BODY = _TextStyle("Helvetica", 10.0, 15.0, (0.10, 0.12, 0.15))
_SPACIOUS_BULLET = _TextStyle("Helvetica", 10.0, 15.0, (0.10, 0.12, 0.15))
_LETTER_NAME = _TextStyle("Helvetica-Bold", 16.0, 22.0, (0.10, 0.18, 0.28))
_LETTER_ROLE = _TextStyle("Helvetica", 10.0, 15.0, (0.23, 0.29, 0.36))
_LETTER_CONTACT = _TextStyle("Helvetica", 10.0, 14.0, (0.30, 0.34, 0.39))
_LETTER_BODY = _TextStyle("Helvetica", 10.0, 15.0, (0.10, 0.12, 0.15))


def _join_section(
    source: ApplicationSource,
    heading: str,
    sentence_ids: tuple[str, ...],
    style_slot_ids: tuple[str, ...],
    *,
    show_heading: bool = True,
    bullet_facts: bool = False,
) -> str:
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    values = [heading] if show_heading else []
    values.extend(slots[slot_id] for slot_id in style_slot_ids)
    values.extend(
        ("• " if bullet_facts else "") + facts[sentence_id]
        for sentence_id in sentence_ids
    )
    return "\n".join(values)


def _join_letter_paragraph(
    source: ApplicationSource,
    sentence_ids: tuple[str, ...],
    style_slot_ids: tuple[str, ...],
) -> str:
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    return " ".join(
        (
            *(slots[slot_id] for slot_id in style_slot_ids),
            *(facts[sentence_id] for sentence_id in sentence_ids),
        )
    )


def _letter_paragraphs(source: ApplicationSource) -> tuple[str, ...]:
    paragraphs = tuple(
        _join_letter_paragraph(
            source,
            section.sentence_ids,
            section.style_slot_ids,
        )
        for section in source.letter_sections
    )
    if not paragraphs or not paragraphs[0].casefold().startswith("dear "):
        paragraphs = ("Dear Hiring Manager,", *paragraphs)
    closing = paragraphs[-1]
    if closing.casefold().startswith(("kind regards", "sincerely")):
        if source.contact.full_name not in closing.splitlines():
            signoff = (
                "Kind regards,"
                if closing.casefold().startswith("kind regards")
                else "Sincerely,"
            )
            paragraphs = (*paragraphs[:-1], f"{signoff}\n{source.contact.full_name}")
    else:
        paragraphs = (*paragraphs, f"Kind regards,\n{source.contact.full_name}")
    return paragraphs


def render_editable_text(source: ApplicationSource) -> EditableArtifacts:
    """Render single-column editable sources and the one canonical answer corpus."""

    verify_application_source(source)
    contact = source.contact
    cv_header = "\n".join(
        value
        for value in (
            contact.full_name,
            source.role_title,
            contact.email,
            contact.phone,
            contact.city,
        )
        if value is not None
    )
    cv = (
        "\n\n".join(
            (
                cv_header,
                *(
                    _join_section(
                        source,
                        section.heading,
                        section.sentence_ids,
                        section.style_slot_ids,
                        bullet_facts=section.heading != "Professional Summary",
                    )
                    for section in source.cv_sections
                ),
            )
        )
        + "\n"
    )
    letter_header = "\n".join(
        value
        for value in (
            contact.full_name,
            contact.email,
            contact.phone,
            contact.city,
            source.role_title,
            source.company_name,
        )
        if value is not None
    )
    letter = (
        "\n\n".join(
            (
                letter_header,
                *_letter_paragraphs(source),
            )
        )
        + "\n"
    )
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    answer_display = "\n\n".join(
        "\n".join(
            (
                answer.question,
                *(slots[value] for value in answer.style_slot_ids),
                *(facts[value] for value in answer.sentence_ids),
            )
        )
        for answer in source.answers
    )
    if answer_display:
        answer_display += "\n"
    assert_employer_facing_text(cv, document_kind="cv")
    assert_employer_facing_text(letter, document_kind="cover_letter")
    if answer_display.strip():
        assert_employer_facing_text(answer_display, document_kind="answer")
    return EditableArtifacts(
        cv_text=cv,
        cover_letter_text=letter,
        answers_text=answer_display,
        cv_sha256=hashlib.sha256(cv.encode("utf-8")).hexdigest(),
        cover_letter_sha256=hashlib.sha256(letter.encode("utf-8")).hexdigest(),
        answers_sha256=hashlib.sha256(answer_display.encode("utf-8")).hexdigest(),
    )


def _text_width(value: str, font_size: float, font_name: str) -> float:
    try:
        value.encode("cp1252")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "PDF text contains characters outside the ATS font encoding"
        ) from exc
    widths = _BOLD_WIDTHS if font_name == "Helvetica-Bold" else _WIDTHS
    return sum(widths.get(character, 1000) for character in value) * font_size / 1000.0


def _wrap_text(
    value: str, *, style: _TextStyle, available_width: float
) -> tuple[str, ...]:
    if any(ord(character) < 32 and character != "\t" for character in value):
        raise ValueError("PDF input contains control characters")
    clean = " ".join(value.expandtabs(4).split())
    if not clean:
        return ()
    bullet_prefix = next(
        (prefix for prefix in ("- ", "• ") if clean.startswith(prefix)),
        "",
    )
    bullet = bool(bullet_prefix)
    words = clean[len(bullet_prefix) :].split(" ") if bullet else clean.split(" ")
    first_prefix = bullet_prefix
    continuation_prefix = "  " if bullet else ""
    lines: list[str] = []
    current = first_prefix
    for word in words:
        if (
            _text_width(continuation_prefix + word, style.font_size, style.font_name)
            > available_width
        ):
            raise ValueError("PDF input contains an unrenderable long token")
        candidate = (
            word
            if not current
            else f"{current}{'' if current.endswith(' ') else ' '}{word}"
        )
        if _text_width(candidate, style.font_size, style.font_name) <= available_width:
            current = candidate
            continue
        if not current.strip(" -"):
            raise ValueError("PDF input contains an unrenderable line")
        lines.append(current.rstrip())
        current = continuation_prefix + word
    if current.strip():
        lines.append(current.rstrip())
    return tuple(lines)


def _layout_blocks(
    blocks: Sequence[Sequence[_LineSpec]], *, max_pages: int
) -> tuple[tuple[PdfLineBox, ...], ...]:
    pages: list[list[PdfLineBox]] = [[]]
    y = TOP_BASELINE

    def new_page() -> None:
        nonlocal y
        if not pages[-1]:
            raise ValueError("PDF layout cannot create an empty page")
        if len(pages) >= max_pages:
            raise ValueError("document content exceeds its deterministic page budget")
        pages.append([])
        y = TOP_BASELINE

    for block in blocks:
        wrapped_block: list[tuple[_LineSpec, tuple[str, ...]]] = []
        for spec in block:
            lines = _wrap_text(
                spec.text,
                style=spec.style,
                available_width=CONTENT_WIDTH - spec.indent,
            )
            if lines:
                wrapped_block.append((spec, lines))
        if not wrapped_block:
            continue
        block_height = sum(
            spec.spacing_before + spec.style.leading * len(lines) + spec.spacing_after
            for spec, lines in wrapped_block
        )
        if (
            pages[-1]
            and block_height <= TOP_BASELINE - BOTTOM_MARGIN
            and y - block_height < BOTTOM_MARGIN
        ):
            new_page()
        # Keep a heading/name with at least its first following line.
        preview = 0.0
        for spec, lines in wrapped_block[:2]:
            preview += spec.spacing_before + spec.style.leading * min(len(lines), 1)
        if y - preview < BOTTOM_MARGIN:
            new_page()
        for spec, lines in wrapped_block:
            y -= spec.spacing_before
            for line in lines:
                width = _text_width(line, spec.style.font_size, spec.style.font_name)
                if y - (spec.style.font_size * 0.22) < BOTTOM_MARGIN:
                    new_page()
                box = PdfLineBox(
                    text=line,
                    x=LEFT_MARGIN + spec.indent,
                    baseline_y=y,
                    width=width,
                    font_size=spec.style.font_size,
                    font_name=spec.style.font_name,
                    role=spec.role,
                    color=spec.style.color,
                )
                pages[-1].append(box)
                y -= spec.style.leading
            y -= spec.spacing_after
    result = tuple(tuple(page) for page in pages)
    validate_pdf_geometry(result)
    return result


def validate_pdf_geometry(pages: tuple[tuple[PdfLineBox, ...], ...]) -> None:
    if not pages or any(not page for page in pages):
        raise ValueError("PDF geometry requires non-empty pages")
    for page in pages:
        previous_bottom = PAGE_HEIGHT - 25.0
        for box in page:
            box.__post_init__()
            if (
                box.x < LEFT_MARGIN
                or box.x + box.width > PAGE_WIDTH - RIGHT_MARGIN + 0.01
                or box.top > PAGE_HEIGHT - 25.0
                or box.bottom < BOTTOM_MARGIN - 0.01
            ):
                raise ValueError("PDF line clips a configured page bound")
            if box.top > previous_bottom + 0.01:
                raise ValueError("PDF line boxes overlap")
            previous_bottom = box.bottom


def _pdf_escape(value: str) -> bytes:
    raw = value.encode("cp1252")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def _number(value: float) -> str:
    rendered = f"{value:.3f}".rstrip("0").rstrip(".")
    return rendered if rendered else "0"


def _content_stream(boxes: tuple[PdfLineBox, ...]) -> bytes:
    commands: list[bytes] = []
    for box in boxes:
        font = "F2" if box.font_name == "Helvetica-Bold" else "F1"
        red, green, blue = box.color
        commands.extend(
            (
                b"q",
                f"{_number(red)} {_number(green)} {_number(blue)} rg".encode(),
                b"BT",
                f"/{font} {_number(box.font_size)} Tf".encode(),
                f"1 0 0 1 {_number(box.x)} {_number(box.baseline_y)} Tm".encode(),
                b"(" + _pdf_escape(box.text) + b") Tj",
                b"ET",
                b"Q",
            )
        )
    return b"\n".join(commands) + b"\n"


def _build_styled_pdf(pages: tuple[tuple[PdfLineBox, ...], ...]) -> bytes:
    validate_pdf_geometry(pages)
    regular_font_id = 3 + (2 * len(pages))
    bold_font_id = regular_font_id + 1
    page_ids = tuple(3 + (index * 2) for index in range(len(pages)))
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: (
            b"<< /Type /Pages /Kids ["
            + b" ".join(f"{value} 0 R".encode() for value in page_ids)
            + f"] /Count {len(pages)} >>".encode()
        ),
        regular_font_id: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        bold_font_id: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    }
    for index, boxes in enumerate(pages):
        page_id = page_ids[index]
        content_id = page_id + 1
        stream = _content_stream(boxes)
        objects[page_id] = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            + f"/Resources << /Font << /F1 {regular_font_id} 0 R /F2 {bold_font_id} 0 R >> >> ".encode()
            + f"/Contents {content_id} 0 R >>".encode()
        )
        objects[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"endstream"
        )
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (bold_font_id + 1)
    for object_id in range(1, bold_font_id + 1):
        offsets[object_id] = len(output)
        output.extend(f"{object_id} 0 obj\n".encode())
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {bold_font_id + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        (
            f"trailer\n<< /Size {bold_font_id + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode()
    )
    return bytes(output)


def _plain_layout_pages(
    pages: tuple[tuple[str, ...], ...],
) -> tuple[tuple[PdfLineBox, ...], ...]:
    if not pages:
        raise ValueError("PDF requires at least one page")
    result: list[tuple[PdfLineBox, ...]] = []
    for values in pages:
        blocks = [
            (_LineSpec(value, "body", _BODY),) for value in values if value.strip()
        ]
        layout = _layout_blocks(blocks, max_pages=1)
        result.append(layout[0])
    return tuple(result)


def _build_text_pdf(pages: tuple[tuple[str, ...], ...]) -> bytes:
    """Compatibility helper: deterministic, width-safe searchable text PDF."""

    return _build_styled_pdf(_plain_layout_pages(pages))


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
    artifact.__post_init__()
    if any(marker in artifact.pdf_bytes for marker in PDF_FORBIDDEN):
        raise ValueError("PDF contains a forbidden rich, hidden or interactive feature")
    layout = artifact.layout_boxes or _plain_layout_pages(artifact.rendered_lines)
    validate_pdf_geometry(layout)
    if artifact.pdf_bytes != _build_styled_pdf(layout):
        raise ValueError(
            "PDF differs from the deterministic text-only subset with geometry binding"
        )
    if hashlib.sha256(artifact.pdf_bytes).hexdigest() != artifact.pdf_sha256:
        raise ValueError("PDF bytes do not match their content hash")
    extracted, pages = _extract_pdf_text(artifact.pdf_bytes)
    if pages != expected_page_count or artifact.page_count != expected_page_count:
        raise ValueError("PDF page count differs from the document contract")
    if (
        extracted != artifact.extracted_text
        or hashlib.sha256(extracted.encode("utf-8")).hexdigest()
        != artifact.extracted_text_sha256
    ):
        raise ValueError("PDF extracted text differs from its retained artifact")
    expected_lines = tuple(box.text.strip() for page in layout for box in page)
    if _normalized_lines(extracted) != expected_lines:
        raise ValueError("PDF parser output differs from deterministic layout order")
    normalized = " ".join(_normalized_lines(extracted))
    for value in required_values:
        if " ".join(value.split()) not in normalized:
            raise ValueError("PDF parser output lost an authoritative value")
    assurance = inspect_pdf_bytes(
        artifact.pdf_bytes,
        document_kind=artifact.document_kind,
    )
    if (
        assurance.document_sha256 != artifact.pdf_sha256
        or assurance.extracted_text_sha256 != artifact.extracted_text_sha256
        or assurance.page_count != artifact.page_count
    ):
        raise ValueError("external-document assurance differs from PDF artifact")


def _artifact(
    document_kind: str,
    layout: tuple[tuple[PdfLineBox, ...], ...] | tuple[tuple[str, ...], ...],
) -> PdfArtifact:
    geometry = (
        _plain_layout_pages(layout)  # type: ignore[arg-type]
        if layout and layout[0] and isinstance(layout[0][0], str)
        else layout
    )
    pdf = _build_styled_pdf(geometry)  # type: ignore[arg-type]
    extracted, page_count = _extract_pdf_text(pdf)
    rendered = tuple(
        tuple(box.text for box in page) for page in geometry  # type: ignore[union-attr]
    )
    return PdfArtifact(
        document_kind=document_kind,
        pdf_bytes=pdf,
        pdf_sha256=hashlib.sha256(pdf).hexdigest(),
        extracted_text=extracted,
        extracted_text_sha256=hashlib.sha256(extracted.encode("utf-8")).hexdigest(),
        page_count=page_count,
        rendered_lines=rendered,
        layout_boxes=geometry,  # type: ignore[arg-type]
    )


def _cv_blocks(source: ApplicationSource) -> list[tuple[_LineSpec, ...]]:
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    contact = " | ".join(
        value
        for value in (source.contact.email, source.contact.phone, source.contact.city)
        if value is not None
    )
    cv_facts = tuple(row for row in source.facts if row.document_kind == "cv")
    spacious = (
        len(cv_facts) <= 10 and sum(len(row.text.split()) for row in cv_facts) <= 220
    )
    name_style = _SPACIOUS_NAME if spacious else _NAME
    role_style = _SPACIOUS_ROLE if spacious else _ROLE
    contact_style = _SPACIOUS_CONTACT if spacious else _CONTACT
    heading_style = _SPACIOUS_HEADING if spacious else _HEADING
    body_style = _SPACIOUS_BODY if spacious else _BODY
    bullet_style = _SPACIOUS_BULLET if spacious else _BULLET
    blocks: list[tuple[_LineSpec, ...]] = [
        (_LineSpec(source.contact.full_name, "name", name_style),),
        (_LineSpec(source.role_title, "target-role", role_style, spacing_after=3.0),),
        (
            _LineSpec(
                contact,
                "contact",
                contact_style,
                spacing_after=15.0 if spacious else 9.0,
            ),
        ),
    ]
    for section in source.cv_sections:
        values: list[_LineSpec] = []
        values.extend(
            _LineSpec(slots[value], "connective", _BODY, spacing_after=1.5)
            for value in section.style_slot_ids
        )
        if section.heading == "Professional Summary":
            if section.sentence_ids:
                values.append(
                    _LineSpec(
                        " ".join(facts[value] for value in section.sentence_ids),
                        "summary",
                        body_style,
                        spacing_after=7.0 if spacious else 2.0,
                    )
                )
        else:
            values.extend(
                _LineSpec(
                    f"• {facts[value]}",
                    "bullet",
                    bullet_style,
                    spacing_after=7.0 if spacious else 2.0,
                    indent=5.0,
                )
                for value in section.sentence_ids
            )
        heading = _LineSpec(
            section.heading,
            "section-heading",
            heading_style,
            spacing_before=11.0 if spacious else 4.0,
            spacing_after=4.0 if spacious else 2.0,
        )
        if not values:
            blocks.append((heading,))
            continue
        blocks.append((heading, values[0]))
        blocks.extend((value,) for value in values[1:])
    return blocks


def _letter_blocks(source: ApplicationSource) -> list[tuple[_LineSpec, ...]]:
    contact = " | ".join(
        value
        for value in (source.contact.email, source.contact.phone, source.contact.city)
        if value is not None
    )
    blocks: list[tuple[_LineSpec, ...]] = [
        (_LineSpec(source.contact.full_name, "name", _LETTER_NAME),),
        (_LineSpec(contact, "contact", _LETTER_CONTACT, spacing_after=10.0),),
        (_LineSpec(source.role_title, "target-role", _LETTER_ROLE),),
        (
            _LineSpec(
                source.company_name,
                "company",
                _LETTER_ROLE,
                spacing_after=12.0,
            ),
        ),
    ]
    paragraphs = _letter_paragraphs(source)
    for index, paragraph in enumerate(paragraphs):
        role = (
            "salutation"
            if index == 0
            else "signature"
            if index == len(paragraphs) - 1
            else "factual-prose"
        )
        lines = paragraph.splitlines()
        blocks.append(
            tuple(
                _LineSpec(
                    line,
                    role,
                    _LETTER_BODY,
                    spacing_before=2.0 if line_index == 0 else 0.0,
                    spacing_after=4.0 if line_index == len(lines) - 1 else 0.0,
                )
                for line_index, line in enumerate(lines)
            )
        )
    return blocks


def render_pdf_artifacts(
    source: ApplicationSource,
) -> ApplicationArtifacts:
    """Render a polished one/two-page CV and one-page cover letter."""

    verify_application_source(source)
    editable = render_editable_text(source)
    cv_layout = _layout_blocks(_cv_blocks(source), max_pages=2)
    letter_layout = _layout_blocks(_letter_blocks(source), max_pages=1)
    cv_pdf = _artifact("cv", cv_layout)
    letter_pdf = _artifact("cover_letter", letter_layout)
    contact_values = tuple(
        value
        for value in (
            source.contact.full_name,
            source.contact.email,
            source.contact.phone,
            source.contact.city,
        )
        if value is not None
    )
    required_cv = (
        *contact_values,
        source.role_title,
        *(row.text for row in source.facts if row.document_kind == "cv"),
    )
    required_letter = (
        *contact_values,
        source.role_title,
        source.company_name,
        *(row.text for row in source.facts if row.document_kind == "cover_letter"),
    )
    validate_pdf_artifact(
        cv_pdf,
        expected_page_count=len(cv_layout),
        required_values=required_cv,
    )
    validate_pdf_artifact(
        letter_pdf,
        expected_page_count=1,
        required_values=required_letter,
    )
    assert_application_artifacts(
        cv_pdf_bytes=cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=letter_pdf.pdf_bytes,
        answers_text=editable.answers_display_text,
        intended_vacancy=IntendedVacancy(
            job_key=source.job_key,
            vacancy_sha256=source.vacancy_sha256,
            role_title=source.role_title,
            company_name=source.company_name,
        ),
    )
    extracted_tokens = set(
        FACT_TOKEN.findall(f"{cv_pdf.extracted_text}\n{letter_pdf.extracted_text}")
    )
    source_tokens = set(
        FACT_TOKEN.findall(f"{editable.cv_text}\n{editable.cover_letter_text}")
    )
    if extracted_tokens != source_tokens:
        raise ValueError("PDF rendering changed dates, metrics or contact tokens")
    artifact_set_sha256 = hashlib.sha256(
        "\n".join(
            (
                source.source_id,
                RENDERER_POLICY_SHA256,
                editable.cv_sha256,
                editable.cover_letter_sha256,
                editable.answers_sha256,
                cv_pdf.pdf_sha256,
                cv_pdf.extracted_text_sha256,
                letter_pdf.pdf_sha256,
                letter_pdf.extracted_text_sha256,
            )
        ).encode("utf-8")
    ).hexdigest()
    return ApplicationArtifacts(
        source_id=source.source_id,
        editable=editable,
        cv_pdf=cv_pdf,
        cover_letter_pdf=letter_pdf,
        artifact_set_sha256=artifact_set_sha256,
    )


def verify_application_artifacts(
    artifacts: ApplicationArtifacts,
    source: ApplicationSource | None = None,
) -> None:
    """Verify exact identities, geometry and optional transitive source truth."""

    artifacts.__post_init__()
    editable = artifacts.editable
    expected_answer_bytes = editable.form_answers_bytes
    if editable.answers_sha256 != hashlib.sha256(expected_answer_bytes).hexdigest():
        raise ValueError("editable answers differ from canonical form-answer bytes")
    for value, digest in (
        (editable.cv_text.encode("utf-8"), editable.cv_sha256),
        (editable.cover_letter_text.encode("utf-8"), editable.cover_letter_sha256),
        (expected_answer_bytes, editable.answers_sha256),
    ):
        if hashlib.sha256(value).hexdigest() != digest:
            raise ValueError("editable artifact differs from its content hash")
    if artifacts.cv_pdf.page_count not in {1, 2}:
        raise ValueError("CV artifact must contain one or two pages")
    validate_pdf_artifact(
        artifacts.cv_pdf,
        expected_page_count=artifacts.cv_pdf.page_count,
        required_values=(),
    )
    validate_pdf_artifact(
        artifacts.cover_letter_pdf,
        expected_page_count=1,
        required_values=(),
    )
    expected = hashlib.sha256(
        "\n".join(
            (
                artifacts.source_id,
                RENDERER_POLICY_SHA256,
                editable.cv_sha256,
                editable.cover_letter_sha256,
                editable.answers_sha256,
                artifacts.cv_pdf.pdf_sha256,
                artifacts.cv_pdf.extracted_text_sha256,
                artifacts.cover_letter_pdf.pdf_sha256,
                artifacts.cover_letter_pdf.extracted_text_sha256,
            )
        ).encode("utf-8")
    ).hexdigest()
    if artifacts.artifact_set_sha256 != expected:
        raise ValueError("artifact-set identity differs from its exact components")
    if source is not None:
        verify_application_source(source)
        if artifacts.source_id != source.source_id:
            raise ValueError("application artifacts cite a different source")
        rebuilt = render_editable_text(source)
        if rebuilt != editable:
            raise ValueError(
                "editable artifacts contain content outside the source manifest"
            )
        expected_cv = _artifact("cv", _layout_blocks(_cv_blocks(source), max_pages=2))
        expected_letter = _artifact(
            "cover_letter", _layout_blocks(_letter_blocks(source), max_pages=1)
        )
        if (
            artifacts.cv_pdf != expected_cv
            or artifacts.cover_letter_pdf != expected_letter
        ):
            raise ValueError("retained PDFs differ from an exact source rerender")
        for fact in source.facts:
            target = {
                "cv": editable.cv_text,
                "cover_letter": editable.cover_letter_text,
                "answer": editable.answers_display_text,
            }[fact.document_kind]
            if target.count(fact.text) != 1:
                raise ValueError("factual span is missing, duplicated or orphaned")


__all__ = [
    "ApplicationArtifacts",
    "EditableArtifacts",
    "PdfArtifact",
    "PdfLineBox",
    "RENDERER_POLICY_SHA256",
    "_build_text_pdf",
    "render_editable_text",
    "render_pdf_artifacts",
    "validate_pdf_artifact",
    "validate_pdf_geometry",
    "verify_application_artifacts",
]
