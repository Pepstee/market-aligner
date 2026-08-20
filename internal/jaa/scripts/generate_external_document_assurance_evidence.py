#!/usr/bin/env python3
"""Generate deterministic machine evidence for the JAA assurance boundary."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path

from career_automation.evidence_matching import canonical_json, content_hash
from career_automation.external_document_assurance import (
    ASSURANCE_POLICY_SHA256,
    ExternalDocumentAssuranceError,
    IntendedVacancy,
    assure_pdf_bytes,
)
from career_automation.rendering import _build_text_pdf


INCIDENT_SHA256 = "3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2"


def _click_inventory(path: Path) -> list[dict[str, object]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    result: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "click":
            continue
        parent: ast.AST | None = node
        while parent is not None and not isinstance(parent, ast.FunctionDef):
            parent = parents.get(parent)
        if not isinstance(parent, ast.FunctionDef):
            raise ValueError("browser click exists outside a function")
        result.append({"function": parent.name, "line": node.lineno})
    return sorted(result, key=lambda row: int(row["line"]))


def _operational_submit_scripts(root: Path) -> tuple[int, list[str]]:
    suffixes = {".py", ".js", ".ts", ".sh"}
    inspected = 0
    capable: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name.startswith("._") or path.suffix not in suffixes:
            continue
        inspected += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"playwright|selenium|puppeteer", text, re.IGNORECASE) and re.search(
            r"\b(?:click|submit)\s*\(", text
        ):
            capable.append(str(path.relative_to(root)))
    return inspected, capable


def build_evidence(
    repository_root: Path,
    incident_pdf: Path,
    operational_root: Path,
) -> dict[str, object]:
    incident_bytes = incident_pdf.read_bytes()
    incident_hash = hashlib.sha256(incident_bytes).hexdigest()
    if incident_hash != INCIDENT_SHA256:
        raise ValueError("operational incident PDF does not match quarantine identity")
    vacancy = IntendedVacancy(
        job_key="assurance-evidence-canary",
        vacancy_sha256=hashlib.sha256(b"assurance evidence vacancy v1").hexdigest(),
        role_title="Graduate Software Engineer",
        company_name="Assurance Fixture Employer",
    )
    clean_pdf = _build_text_pdf(
        (("Artiom Gutu", "Graduate software engineer", "First-Class Honours"),)
    )
    clean_receipt = assure_pdf_bytes(
        clean_pdf,
        document_kind="cv",
        intended_vacancy=vacancy,
    )
    try:
        assure_pdf_bytes(
            incident_bytes,
            document_kind="cv",
            intended_vacancy=vacancy,
        )
    except ExternalDocumentAssuranceError as error:
        incident_result = {
            "verdict": "block",
            "document_sha256": incident_hash,
            "finding_codes": [finding.code for finding in error.findings],
        }
    else:  # pragma: no cover - a generation-time certification failure
        raise RuntimeError("quarantined incident PDF unexpectedly passed")
    inspected_scripts, alternate_scripts = _operational_submit_scripts(
        operational_root
    )
    preimage: dict[str, object] = {
        "schema_version": "jaa.external-document-assurance-evidence.v1",
        "evidence_date": "2026-08-05",
        "policy_sha256": ASSURANCE_POLICY_SHA256,
        "incident": incident_result,
        "clean_control": clean_receipt.document(),
        "enumerated_repository_clicks": _click_inventory(
            repository_root / "career_automation" / "browser_executor.py"
        ),
        "operational_script_scan": {
            "scope": "migrated operational-state Python/JavaScript/TypeScript/shell files",
            "inspected_script_count": inspected_scripts,
            "alternate_browser_submit_scripts": alternate_scripts,
            "alternate_browser_submit_scripts_found": len(alternate_scripts),
            "certification_limit": (
                "JAA repository executor and migrated operational scripts only; "
                "arbitrary human/browser clicks are outside this evidence"
            ),
        },
    }
    return {**preimage, "evidence_sha256": content_hash(preimage)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-pdf", required=True, type=Path)
    parser.add_argument("--operational-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    evidence = build_evidence(root, args.incident_pdf, args.operational_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(canonical_json(evidence) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
