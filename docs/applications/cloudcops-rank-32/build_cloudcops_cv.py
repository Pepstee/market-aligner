"""Build the evidence-bound CloudCops canary CV.

The builder deliberately receives the authoritative contact record and approved
evidence packet as explicit inputs. It does not keep candidate contact details
or biographical claims in source code.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)


REQUIRED_EVIDENCE_IDS = {
    "E-001",
    "E-002",
    "E-006",
    "E-007",
    "E-011",
    "E-012",
    "E-013",
}


def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _approved_statements(packet: dict[str, object]) -> dict[str, str]:
    if packet.get("schema_version") != "jaa05.operator-approved-statements.v1":
        raise ValueError("unsupported evidence packet")
    statements = packet.get("statements")
    if not isinstance(statements, list):
        raise ValueError("evidence packet statements are missing")
    indexed = {
        str(item["id"]): str(item["statement"])
        for item in statements
        if isinstance(item, dict) and "id" in item and "statement" in item
    }
    missing = sorted(REQUIRED_EVIDENCE_IDS - indexed.keys())
    if missing:
        raise ValueError(f"approved evidence is missing: {', '.join(missing)}")
    return indexed


def _contact(record: dict[str, object]) -> dict[str, str]:
    candidate = record.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("authoritative candidate record is missing")
    required = ("first_name", "last_name", "email", "phone", "current_location")
    values: dict[str, str] = {}
    for key in required:
        value = candidate.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"authoritative candidate value is missing: {key}")
        values[key] = value.strip()
    return values


def build(contact: dict[str, str], evidence: dict[str, str], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    regular_font = "/System/Library/Fonts/Supplemental/Arial.ttf"
    bold_font = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
    pdfmetrics.registerFont(TTFont("Arial", regular_font))
    pdfmetrics.registerFont(TTFont("Arial-Bold", bold_font))

    ink = colors.HexColor("#111827")
    blue = colors.HexColor("#174E75")
    muted = colors.HexColor("#4B5563")
    line = colors.HexColor("#CBD5E1")
    base = getSampleStyleSheet()
    name_style = ParagraphStyle(
        "Name", parent=base["Normal"], fontName="Arial-Bold", fontSize=22,
        leading=25, textColor=ink, alignment=TA_CENTER, spaceAfter=3,
    )
    headline = ParagraphStyle(
        "Headline", parent=base["Normal"], fontName="Arial", fontSize=10.5,
        leading=13, textColor=blue, alignment=TA_CENTER, spaceAfter=4,
    )
    contact_style = ParagraphStyle(
        "Contact", parent=base["Normal"], fontName="Arial", fontSize=8.7,
        leading=11, textColor=muted, alignment=TA_CENTER, spaceAfter=7,
    )
    section = ParagraphStyle(
        "Section", parent=base["Heading2"], fontName="Arial-Bold",
        fontSize=10.5, leading=13, textColor=blue, spaceBefore=7,
        spaceAfter=3, keepWithNext=True,
    )
    body = ParagraphStyle(
        "Body", parent=base["Normal"], fontName="Arial", fontSize=9.2,
        leading=12, textColor=ink, spaceAfter=4,
    )
    role = ParagraphStyle(
        "Role", parent=body, fontName="Arial-Bold", fontSize=9.6,
        leading=12, spaceBefore=3, spaceAfter=1, keepWithNext=True,
    )
    meta = ParagraphStyle(
        "Meta", parent=body, fontSize=8.8, leading=11, textColor=muted,
        spaceAfter=2,
    )
    bullet = ParagraphStyle(
        "Bullet", parent=body, leftIndent=4.5 * mm,
        firstLineIndent=-3.2 * mm, bulletIndent=0, spaceAfter=2,
    )

    def heading(text: str) -> list[object]:
        return [
            Paragraph(text.upper(), section),
            HRFlowable(width="100%", thickness=0.6, color=line, spaceAfter=4),
        ]

    def bullets(items: list[str]) -> list[Paragraph]:
        return [Paragraph(f"• {item}", bullet) for item in items]

    full_name = f"{contact['first_name']} {contact['last_name']}"
    story: list[object] = [
        Paragraph(full_name.upper(), name_style),
        Paragraph(
            "Junior Cloud and Automation Engineer | Python, AWS and Reliable Systems",
            headline,
        ),
        Paragraph(
            f"{contact['current_location']} &nbsp;|&nbsp; {contact['phone']} "
            f"&nbsp;|&nbsp; {contact['email']} &nbsp;|&nbsp; "
            '<link href="https://github.com/Pepstee" '
            'color="#174E75">github.com/Pepstee</link>',
            contact_style,
        ),
    ]

    story += heading("Profile")
    story.append(Paragraph(
        "First-Class Computer Science graduate focused on cloud automation, "
        "dependable software workflows and systems that fail safely. My "
        "university work investigated anomaly detection within AWS Lambda "
        "environments, while my current projects cover structured data, "
        "validation, testing, resumable execution and auditable automation. I "
        "am looking for an entry-level role where I can deepen practical cloud "
        "and infrastructure engineering skills.",
        body,
    ))

    story += heading("Technical focus")
    story += bullets([
        "Python automation, structured JSON data, SQLite, APIs and deterministic validation.",
        "AWS Lambda and CloudWatch telemetry through the SCAFAD dissertation project.",
        "GitHub-based software projects, automated tests, retries, caching, resumability and audit trails.",
        "Security-conscious design, privacy, adversarial testing and fail-closed operational controls.",
    ])

    story += heading("Selected projects")
    story.append(KeepTogether([
        Paragraph("SCAFAD | First-Class Computer Science dissertation", role),
        Paragraph("AWS Lambda, CloudWatch telemetry, Python and anomaly detection", meta),
        *bullets([
            "Investigated anomaly detection within AWS Lambda environments using serverless telemetry.",
            "Worked across telemetry collection, graph-based analysis, privacy, adversarial testing, explainability and research evaluation.",
            "This was an undergraduate research and engineering project, not professional production-security employment.",
        ]),
    ]))
    story.append(KeepTogether([
        Paragraph("Market Aligner | Job-intelligence and automation system", role),
        Paragraph("Python workflow, SQLite persistence, validation and resumability", meta),
        *bullets([
            "Directed AI agents implementing collectors, validation, caching, SQLite persistence, retries and resumability.",
            "Defined the product requirements and evidence boundaries, then tested and reviewed the resulting system.",
            "I do not present the AI-generated implementation as code that I personally hand-wrote.",
        ]),
    ]))
    story.append(KeepTogether([
        Paragraph("Multi-agent software factory | Reliable AI-assisted delivery", role),
        Paragraph("System architecture, operational control, testing and evaluation", meta),
        *bullets([
            "Own the requirements, system architecture, operation, evaluation and acceptance decisions.",
            "Designed bounded workflows around planning, implementation, independent review, certification and recovery.",
            "AI agents generated substantial implementation code; my role is accurately described as architecture, direction, operation and acceptance.",
        ]),
    ]))

    story += heading("Education")
    story.extend([
        Paragraph("BSc (Hons) Computer Science, First-Class Honours", role),
        Paragraph("Birmingham Newman University | Graduated 2 July 2026", meta),
        Paragraph(
            "Final-year dissertation: SCAFAD, investigating anomaly detection "
            "within AWS Lambda environments using serverless telemetry.",
            body,
        ),
    ])

    story += heading("Additional experience")
    story += bullets([
        "Paid online English tutoring, requiring clear explanation and adaptation to individual learners.",
        "Customer-facing direct sales in Birmingham, including recruitment, training or coaching of new starters; this was not a B2B role.",
    ])
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "Evidence boundary: project implementation used substantial AI-generated "
        "code under my direction. Claims in this CV are limited to the operator-approved evidence record.",
        meta,
    ))

    document = SimpleDocTemplate(
        str(output), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
        topMargin=13 * mm, bottomMargin=13 * mm,
        title=f"{full_name} - CloudCops CV",
        author=full_name,
    )
    document.build(story)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contact-record", type=Path, required=True)
    parser.add_argument("--evidence-packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contact = _contact(_load_json(args.contact_record))
    evidence = _approved_statements(_load_json(args.evidence_packet))
    build(contact, evidence, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
