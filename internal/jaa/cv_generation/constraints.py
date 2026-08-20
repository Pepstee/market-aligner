"""Deterministic, candidate-ratified constraints for generated CVs.

This module owns presentation policy.  It receives primitive, immutable
rendering facts so it neither depends on form filling nor reaches into core
application state.  Generation must fail before publication when this gate
rejects an artifact.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DAY_MONTH_YEAR = re.compile(
    r"\b(?:[1-9]|[12]\d|3[01])\s+"
    r"(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+20\d{2}\b",
    re.IGNORECASE,
)
_WORK_RIGHTS = (
    "right to work",
    "work rights",
    "work authorisation",
    "work authorization",
    "visa status",
    "visa sponsorship",
    "sponsorship required",
    "sponsorship not required",
    "settled status",
    "pre-settled status",
)
_FORMAT_INVENTORY = re.compile(
    r"(?:^|[,|;/]\s*)(?:jsonl?|ya?ml|xml|csv|sqlite|sql)(?:\s*[,|;/]|$)",
    re.IGNORECASE,
)
_REJECTION_SIGNAL = re.compile(
    r"\b(?:ai[- ](?:generated|assisted)|built (?:by|with) ai|ai agents?|"
    r"honesty note|full disclosure|internal (?:process|review|workflow)|"
    r"missing (?:skill|experience)|lack(?:ing|s)? (?:skill|experience)|"
    r"not (?:proficient|experienced|qualified)|implementation attribution|"
    r"production mastery (?:is )?not proved)\b",
    re.IGNORECASE,
)
_STALE_OR_IRRELEVANT = re.compile(
    r"\b(?:GCSEs?|front[- ]end (?:website|project)|British Chamber of Commerce|"
    r"Counter Trafficking Network|DHL operative)\b|\b2022\b",
    re.IGNORECASE,
)
_TOOL_TOKEN = re.compile(
    r"\b(?:python|javascript|typescript|html5?|css3?|php|lua|shell|git|github|"
    r"docker|aws lambda|runpod|hugging face|pytest|unittest|robot framework|"
    r"wireshark|nmap|metasploit|hydra|nikto|wordpress|axure|slack|"
    r"microsoft office|windows|linux|macos|jsonl?|ya?ml|xml|csv|sqlite|sql)\b",
    re.IGNORECASE,
)
_CAPABILITY_LANGUAGE = re.compile(
    r"\b(?:orchestration|systems? design|architecture|automation|engineering|"
    r"development|testing|assurance|security|analysis|delivery|integration|"
    r"research|evaluation|reliability|observability|model routing)\b",
    re.IGNORECASE,
)
_STANDARD_HEADINGS = (
    "Professional Summary",
    "Core Capabilities",
    "Projects",
    "Experience",
    "Education",
    "Certifications",
)


class CVConstraintError(ValueError):
    """The generated CV violates a deterministic presentation constraint."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class CVPolicy:
    schema_version: str
    candidate_name: str | None = None
    required_city: str | None = None
    required_graduation: str | None = None
    required_dissertation_title: str | None = None
    required_capabilities_heading: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != "jaa.cv-policy.v1":
            raise ValueError("unsupported CV policy schema")
        if self.candidate_name is None and any(
            value is not None
            for value in (
                self.required_city,
                self.required_graduation,
                self.required_dissertation_title,
                self.required_capabilities_heading,
            )
        ):
            raise ValueError("candidate-specific CV rules require a candidate name")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "candidate_name": self.candidate_name,
            "required_city": self.required_city,
            "required_graduation": self.required_graduation,
            "required_dissertation_title": self.required_dissertation_title,
            "required_capabilities_heading": self.required_capabilities_heading,
            "universal_rules": {
                "document_labels_forbidden": ["Curriculum Vitae", "CV"],
                "work_rights_forbidden": list(_WORK_RIGHTS),
                "graduation_day_forbidden": True,
                "continuation_banner_forbidden": True,
                "format_inventory_as_skill_forbidden": True,
                "tool_inventory_as_capability_forbidden": True,
                "volunteered_rejection_signals_forbidden": True,
                "target_role_as_current_identity_forbidden": True,
                "ats_single_column_text_only": True,
            },
        }

    @property
    def policy_sha256(self) -> str:
        return _digest(_canonical_json(self.document()).encode())


BASE_CV_POLICY = CVPolicy("jaa.cv-policy.v1")
ARTIOM_GUTU_CV_POLICY = CVPolicy(
    "jaa.cv-policy.v1",
    candidate_name="Artiom Gutu",
    required_city="Birmingham, United Kingdom",
    required_graduation="July 2026",
    required_dissertation_title=(
        "SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
        "Anomaly-Detection Pipeline for Serverless Workloads"
    ),
    required_capabilities_heading="Core Capabilities",
)


def policy_for_candidate(full_name: str) -> CVPolicy:
    return (
        ARTIOM_GUTU_CV_POLICY
        if " ".join(full_name.casefold().split()) == "artiom gutu"
        else BASE_CV_POLICY
    )


@dataclass(frozen=True)
class CVConstraintReceipt:
    source_id: str
    cv_sha256: str
    policy_sha256: str
    receipt_sha256: str
    passed: bool = True
    release_authority: bool = False

    def __post_init__(self) -> None:
        for value in (
            self.source_id,
            self.cv_sha256,
            self.policy_sha256,
            self.receipt_sha256,
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError("CV constraint receipt hashes must be SHA-256")
        if self.passed is not True or self.release_authority is not False:
            raise ValueError("CV constraint receipts cannot grant release authority")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.cv-constraint-receipt.v1",
            "source_id": self.source_id,
            "cv_sha256": self.cv_sha256,
            "policy_sha256": self.policy_sha256,
            "passed": True,
            "release_authority": False,
            "receipt_sha256": self.receipt_sha256,
        }


def _section_text(
    sections: Mapping[str, Sequence[str]],
    heading: str,
) -> str:
    return "\n".join(sections.get(heading, ()))


def validate_generated_cv(
    *,
    source_id: str,
    candidate_name: str,
    candidate_city: str,
    cv_text: str,
    cv_sha256: str,
    sections: Mapping[str, Sequence[str]],
    rendered_pages: Iterable[Sequence[str]],
    policy: CVPolicy | None = None,
    target_role_title: str | None = None,
) -> CVConstraintReceipt:
    """Fail closed on forbidden CV content and candidate-specific invariants."""
    selected = policy or policy_for_candidate(candidate_name)
    if not _SHA256.fullmatch(source_id) or not _SHA256.fullmatch(cv_sha256):
        raise CVConstraintError("CV generation identities must be SHA-256")
    if _digest(cv_text.encode()) != cv_sha256:
        raise CVConstraintError("CV text differs from its retained hash")
    folded = cv_text.casefold()
    if "curriculum vitae" in folded or re.search(r"(?m)^\s*cv\s*$", cv_text, re.I):
        raise CVConstraintError("CV document labels are forbidden")
    work_rights = next((value for value in _WORK_RIGHTS if value in folded), None)
    if work_rights is not None:
        raise CVConstraintError("work-rights and visa declarations are forbidden in CVs")
    if _REJECTION_SIGNAL.search(cv_text):
        raise CVConstraintError("volunteered rejection signals are forbidden in CVs")

    headings = tuple(sections)
    if not headings or headings[0] != "Professional Summary":
        raise CVConstraintError("CV hierarchy must start with Professional Summary")
    if any(heading not in _STANDARD_HEADINGS for heading in headings):
        raise CVConstraintError("CV uses a non-standard ATS section heading")
    if "Core Capabilities" not in headings:
        raise CVConstraintError("capability-led skills are required")
    if "Projects" in headings and headings.index("Core Capabilities") > headings.index("Projects"):
        raise CVConstraintError("Core Capabilities must precede Projects")

    if target_role_title is not None:
        role = " ".join(target_role_title.casefold().split())
        summary_lines = tuple(
            " ".join(line.casefold().strip(" :.-").split())
            for line in sections.get("Professional Summary", ())
        )
        if any(line == role or line.startswith(f"target role {role}") for line in summary_lines):
            raise CVConstraintError("target role cannot masquerade as current identity")

    education = _section_text(sections, "Education")
    if _DAY_MONTH_YEAR.search(education):
        raise CVConstraintError("graduation dates must use month and year only")
    for heading in ("Skills", "Core Capabilities"):
        section_text = _section_text(sections, heading)
        if _FORMAT_INVENTORY.search(section_text):
            raise CVConstraintError(
                "formats, interchange syntax and storage engines cannot be listed as skills"
            )
        for line in sections.get(heading, ()):
            if len(_TOOL_TOKEN.findall(line)) >= 2 and not _CAPABILITY_LANGUAGE.search(line):
                raise CVConstraintError(
                    "tools and platforms must support a capability, not replace one"
                )

    pages = tuple(tuple(page) for page in rendered_pages)
    if not pages:
        raise CVConstraintError("CV rendering must contain at least one page")
    for page in pages[1:]:
        visible = tuple(line.strip() for line in page if line.strip())
        if visible and (
            visible[0].casefold() == candidate_name.casefold()
            or visible[0].casefold() in {"cv", "curriculum vitae"}
        ):
            raise CVConstraintError("continuation pages cannot repeat a CV banner")

    if selected.candidate_name is not None:
        if candidate_name != selected.candidate_name:
            raise CVConstraintError("candidate-specific policy has the wrong candidate")
        if candidate_city != selected.required_city:
            raise CVConstraintError("CV location differs from candidate authority")
        if selected.required_city not in cv_text:
            raise CVConstraintError("required CV location is absent")
        if selected.required_graduation not in education:
            raise CVConstraintError("required month-and-year graduation is absent")
        if selected.required_dissertation_title not in education:
            raise CVConstraintError("canonical dissertation title is absent")
        if selected.required_capabilities_heading not in sections:
            raise CVConstraintError("professional capabilities section is absent")
        if "Projects" not in sections:
            raise CVConstraintError("verified projects section is required")
        if _STALE_OR_IRRELEVANT.search(cv_text):
            raise CVConstraintError("stale or irrelevant candidate detail is forbidden")

    receipt_body = {
        "schema_version": "jaa.cv-constraint-receipt.v1",
        "source_id": source_id,
        "cv_sha256": cv_sha256,
        "policy_sha256": selected.policy_sha256,
        "passed": True,
        "release_authority": False,
    }
    return CVConstraintReceipt(
        source_id=source_id,
        cv_sha256=cv_sha256,
        policy_sha256=selected.policy_sha256,
        receipt_sha256=_digest(_canonical_json(receipt_body).encode()),
    )


__all__ = [
    "ARTIOM_GUTU_CV_POLICY",
    "BASE_CV_POLICY",
    "CVConstraintError",
    "CVConstraintReceipt",
    "CVPolicy",
    "policy_for_candidate",
    "validate_generated_cv",
]
