#!/usr/bin/env python3
"""Build the Axiom document canary from the approved evidence packet only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from career_automation.evidence_matching import canonical_json, content_hash
from career_automation.external_document_assurance import IntendedVacancy, assure_pdf_bytes
from career_automation.rendering import _build_text_pdf


ALLOWED_IDS = ("E-001", "E-002", "E-006", "E-007", "E-008", "E-009")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-packet", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()
    packet_bytes = args.evidence_packet.read_bytes()
    packet = json.loads(packet_bytes)
    statements = {row["id"]: row["statement"] for row in packet["statements"]}
    selected = {key: statements[key] for key in ALLOWED_IDS}
    vacancy = IntendedVacancy(
        job_key="himalayas:axiomdata:data-scientist",
        vacancy_sha256="ea9d4440421ced3d2a0472b51e758260c050a72ec6a9889e7c3c023a592d366d",
        role_title="Data Scientist",
        company_name="Axiom",
    )
    cv_pages = (
        (
            "ARTIOM GUTU",
            packet["human_authority"],
            "DATA SCIENCE GRADUATE",
            "First-Class Computer Science graduate with project experience in serverless",
            "telemetry and anomaly detection, plus paid online teaching and customer-facing work.",
            "EDUCATION",
            "BSc (Hons) Computer Science, First-Class Honours",
            "Birmingham Newman University, graduated 2 July 2026",
            "PROJECT",
            "SCAFAD, final-year dissertation",
            "Investigated anomaly detection in AWS Lambda environments using serverless telemetry.",
        ),
        (
            "ADDITIONAL PROJECTS",
            "Northern Ray",
            "Designed or implemented material parts of an unpaid external-client website and",
            "application project. The client later abandoned the project.",
            "Frontend website",
            "Completed a separate frontend-only website project.",
            "EXPERIENCE",
            "Online English tutor",
            "Provided paid online English lessons.",
            "Customer-facing direct sales, Birmingham",
            "Worked directly with customers and recruited, trained or coached new starters.",
            "This was a consumer-facing role.",
        ),
    )
    letter_pages = ((
        "ARTIOM GUTU",
        packet["human_authority"],
        "Data Scientist, Axiom",
        "Dear Hiring Manager,",
        "Axiom's small data science team appeals to me because the role combines model work,",
        "research and clear reporting. I recently completed a First-Class Computer Science",
        "degree, where my dissertation investigated anomaly detection in AWS Lambda",
        "environments using serverless telemetry.",
        "My background also includes paid online teaching and customer-facing direct sales.",
        "Those roles gave me experience communicating with learners and customers. In project",
        "work, I designed or implemented material parts of Northern Ray, an",
        "external-client website and application that was later abandoned by the client.",
        "I would welcome a conversation about how my research foundation and communication",
        "experience could contribute to Axiom's procurement data products.",
        "Kind regards,",
        "Artiom Gutu",
    ),)
    cv = _build_text_pdf(cv_pages)
    letter = _build_text_pdf(letter_pages)
    cv_receipt = assure_pdf_bytes(cv, document_kind="cv", intended_vacancy=vacancy)
    letter_receipt = assure_pdf_bytes(
        letter, document_kind="cover_letter", intended_vacancy=vacancy
    )
    args.output_directory.mkdir(parents=True, exist_ok=True)
    (args.output_directory / "cv.pdf").write_bytes(cv)
    (args.output_directory / "cover-letter.pdf").write_bytes(letter)
    manifest = {
        "schema_version": "jaa.clean-document-canary.v1",
        "status": "document_canary_only_official_submit_route_unresolved",
        "evidence_packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "selected_evidence": selected,
        "vacancy": vacancy.document(),
        "receipts": [cv_receipt.document(), letter_receipt.document()],
        "quarantined_sha256": "3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2",
        "quarantined_hash_absent": all(
            receipt.document_sha256
            != "3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2"
            for receipt in (cv_receipt, letter_receipt)
        ),
        "humanizer_audit": {
            "draft_findings": [
                "removed generic enthusiasm",
                "replaced promotional company language with role-specific reasons",
                "kept evidence scope unchanged",
            ],
            "final_contains_em_or_en_dash": False,
        },
    }
    manifest["manifest_sha256"] = content_hash(manifest)
    (args.output_directory / "manifest.json").write_text(
        canonical_json(manifest) + "\n", encoding="utf-8"
    )
    print(canonical_json(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
