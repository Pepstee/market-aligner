"""Deterministic, candidate-ratified constraints for generated CVs.

This module owns presentation policy.  It receives primitive, immutable
rendering facts so it neither depends on form filling nor reaches into core
application state.  Generation must fail before publication when this gate
rejects an artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DAY_MONTH_YEAR = re.compile(
    r"\b(?:[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?\s+"
    r"(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+20\d{2}\b",
    re.IGNORECASE,
)
_NUMERIC_DAY_DATE = re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-]20\d{2}\b")
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
    "eligible to work",
    "eligibility to work",
    "authorised to work",
    "authorized to work",
    "visa not required",
    "no visa required",
    "sponsorship not needed",
    "no sponsorship needed",
    "unrestricted employment",
)
_WORK_RIGHTS_PARAPHRASE = re.compile(
    r"\b(?:permission|eligibility) (?:for|to) work\b|"
    r"\b(?:do(?:es)? not|don't) require (?:visa )?sponsorship\b",
    re.IGNORECASE,
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
    r"production mastery (?:is )?not proved|agent[- ]assisted|machine[- ]generated|"
    r"llm[- ]produced|human[- ]in[- ]the[- ]loop authorship|"
    r"(?:written|created|coded|developed|implemented|produced)\s+"
    r"(?:with|using|through)\s+(?:generative ai|llms?|coding agents?|automated agents?)|"
    r"(?:code|implementation) (?:was )?(?:produced|generated) (?:through|by) "
    r"(?:automation|agents?|ai))\b",
    re.IGNORECASE,
)
_STALE_OR_IRRELEVANT = re.compile(
    r"\b(?:GCSEs?|front[- ]end (?:website|project)|British Chamber of Commerce|"
    r"Counter Trafficking Network|DHL operative)\b",
    re.IGNORECASE,
)
_IRRELEVANT_EXPERIENCE = re.compile(
    r"\b(?:laboratory assistant|translator(?: and interpreter)?|interpreter|"
    r"chamber of commerce assistant|warehouse operative|door[- ]to[- ]door sales)\b",
    re.IGNORECASE,
)
_GENERIC_FILLER = re.compile(
    r"\b(?:motivated professional|passionate individual|results[- ]driven|"
    r"dynamic self[- ]starter|hard[- ]working|excellent communication skills|"
    r"seeking (?:a|an|the) (?:challenging|exciting) opportunity)\b",
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


def _fold_display_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    normalized = "".join(character for character in normalized if not unicodedata.combining(character))
    return normalized.translate(str.maketrans({"‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-"})).casefold()


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
    required_city="Birmingham",
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


@dataclass(frozen=True)
class CandidateSourcePolicyReceipt:
    """Pre-render source check; deliberately inadmissible as a final CV gate."""

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
                raise ValueError("candidate source policy hashes must be SHA-256")
        if self.passed is not True or self.release_authority is not False:
            raise ValueError("candidate source policy cannot grant release authority")
        body = {
            "schema_version": "jaa.candidate-source-policy-receipt.v1",
            "source_id": self.source_id,
            "cv_sha256": self.cv_sha256,
            "policy_sha256": self.policy_sha256,
            "passed": True,
            "release_authority": False,
        }
        if self.receipt_sha256 != _digest(_canonical_json(body).encode()):
            raise ValueError("candidate source policy receipt identity is invalid")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.candidate-source-policy-receipt.v1",
            "source_id": self.source_id,
            "cv_sha256": self.cv_sha256,
            "policy_sha256": self.policy_sha256,
            "passed": True,
            "release_authority": False,
            "receipt_sha256": self.receipt_sha256,
        }


@dataclass(frozen=True)
class CVPopplerQualityReceipt:
    """Immutable evidence that Poppler parsed and rendered the retained PDF."""

    cv_pdf_sha256: str
    extracted_text_sha256: str
    rendered_page_sha256s: tuple[str, ...]
    pdfinfo_sha256: str
    pdftotext_sha256: str
    pdftoppm_sha256: str
    poppler_version: str
    receipt_sha256: str
    passed: bool = True
    release_authority: bool = False

    def __post_init__(self) -> None:
        hashes = (
            self.cv_pdf_sha256,
            self.extracted_text_sha256,
            self.pdfinfo_sha256,
            self.pdftotext_sha256,
            self.pdftoppm_sha256,
            self.receipt_sha256,
            *self.rendered_page_sha256s,
        )
        if not hashes or any(not _SHA256.fullmatch(value) for value in hashes):
            raise ValueError("Poppler quality receipt hashes must be SHA-256")
        if not self.rendered_page_sha256s:
            raise ValueError("Poppler quality receipt requires rendered pages")
        if not self.poppler_version.strip():
            raise ValueError("Poppler quality receipt requires a version")
        if self.passed is not True or self.release_authority is not False:
            raise ValueError("Poppler quality receipts cannot grant release authority")
        if self.receipt_sha256 != _digest(_canonical_json(self._body()).encode()):
            raise ValueError("Poppler quality receipt does not match its contents")

    @property
    def page_count(self) -> int:
        return len(self.rendered_page_sha256s)

    def _body(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.cv-poppler-quality-receipt.v1",
            "cv_pdf_sha256": self.cv_pdf_sha256,
            "extracted_text_sha256": self.extracted_text_sha256,
            "rendered_page_sha256s": list(self.rendered_page_sha256s),
            "page_count": len(self.rendered_page_sha256s),
            "pdfinfo_sha256": self.pdfinfo_sha256,
            "pdftotext_sha256": self.pdftotext_sha256,
            "pdftoppm_sha256": self.pdftoppm_sha256,
            "poppler_version": self.poppler_version,
            "passed": True,
            "release_authority": False,
        }

    def document(self) -> dict[str, object]:
        return {**self._body(), "receipt_sha256": self.receipt_sha256}


def _regular_file(path: Path, *, label: str) -> os.stat_result:
    try:
        result = path.lstat()
    except OSError as exc:
        raise CVConstraintError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(result.st_mode) or not stat.S_ISREG(result.st_mode):
        raise CVConstraintError(f"{label} must be a regular non-symlink file")
    return result


def _stable_file_identity(path: Path, before: os.stat_result, *, label: str) -> None:
    after = _regular_file(path, label=label)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise CVConstraintError(f"{label} changed during Poppler verification")


def verify_poppler_cv_quality(
    pdf_path: str | Path,
    *,
    expected_pdf_sha256: str,
    expected_page_count: int,
    required_text_markers: Sequence[str],
    poppler_bin_dir: str | Path,
    poppler_library_dir: str | Path | None = None,
) -> CVPopplerQualityReceipt:
    """Parse, extract and rasterise one retained CV using pinned Poppler tools."""
    if not _SHA256.fullmatch(expected_pdf_sha256):
        raise CVConstraintError("expected PDF identity must be SHA-256")
    if expected_page_count < 1:
        raise CVConstraintError("expected page count must be positive")
    markers = tuple(marker.strip() for marker in required_text_markers)
    if not markers or any(not marker for marker in markers):
        raise CVConstraintError("Poppler verification requires non-empty text markers")

    supplied_pdf = Path(pdf_path)
    pdf_identity = _regular_file(supplied_pdf, label="CV PDF")
    retained_pdf = supplied_pdf.resolve(strict=True)
    pdf_bytes = retained_pdf.read_bytes()
    if _digest(pdf_bytes) != expected_pdf_sha256:
        raise CVConstraintError("retained CV PDF differs from its approved hash")

    bin_dir = Path(poppler_bin_dir).resolve(strict=True)
    executables = {
        name: bin_dir / name for name in ("pdfinfo", "pdftotext", "pdftoppm")
    }
    executable_hashes: dict[str, str] = {}
    for name, executable in executables.items():
        _regular_file(executable, label=name)
        executable_hashes[name] = _digest(executable.read_bytes())

    environment = os.environ.copy()
    if poppler_library_dir is not None:
        library_dir = Path(poppler_library_dir).resolve(strict=True)
        if not library_dir.is_dir():
            raise CVConstraintError("Poppler library directory is unavailable")
        environment["LD_LIBRARY_PATH"] = str(library_dir)

    def run(arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                list(arguments),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CVConstraintError("Poppler quality verification failed") from exc

    version_result = run((str(executables["pdfinfo"]), "-v"))
    version = (version_result.stderr or version_result.stdout).decode(
        "utf-8", errors="strict"
    ).splitlines()[0].strip()
    info = run((str(executables["pdfinfo"]), str(retained_pdf))).stdout.decode(
        "utf-8", errors="strict"
    )
    page_match = re.search(r"(?m)^Pages:\s*(\d+)\s*$", info)
    if page_match is None or int(page_match.group(1)) != expected_page_count:
        raise CVConstraintError("Poppler reported an unexpected CV page count")

    text_bytes = run(
        (str(executables["pdftotext"]), "-layout", str(retained_pdf), "-")
    ).stdout
    text = text_bytes.decode("utf-8", errors="strict")
    if "\ufffd" in text or any(marker not in text for marker in markers):
        raise CVConstraintError("Poppler extraction lost required CV text")

    with tempfile.TemporaryDirectory(prefix="jaa-poppler-") as temp_dir:
        prefix = Path(temp_dir) / "page"
        run(
            (
                str(executables["pdftoppm"]),
                "-png",
                "-r",
                "72",
                str(retained_pdf),
                str(prefix),
            )
        )
        rendered = sorted(Path(temp_dir).glob("page-*.png"))
        if len(rendered) != expected_page_count:
            raise CVConstraintError("Poppler rendered an unexpected number of CV pages")
        rendered_bytes = tuple(page.read_bytes() for page in rendered)
        if any(not value.startswith(b"\x89PNG\r\n\x1a\n") for value in rendered_bytes):
            raise CVConstraintError("Poppler produced an invalid CV page image")
        rendered_hashes = tuple(_digest(value) for value in rendered_bytes)

    _stable_file_identity(supplied_pdf, pdf_identity, label="CV PDF")
    body = {
        "schema_version": "jaa.cv-poppler-quality-receipt.v1",
        "cv_pdf_sha256": expected_pdf_sha256,
        "extracted_text_sha256": _digest(text_bytes),
        "rendered_page_sha256s": list(rendered_hashes),
        "page_count": len(rendered_hashes),
        "pdfinfo_sha256": executable_hashes["pdfinfo"],
        "pdftotext_sha256": executable_hashes["pdftotext"],
        "pdftoppm_sha256": executable_hashes["pdftoppm"],
        "poppler_version": version,
        "passed": True,
        "release_authority": False,
    }
    return CVPopplerQualityReceipt(
        cv_pdf_sha256=expected_pdf_sha256,
        extracted_text_sha256=_digest(text_bytes),
        rendered_page_sha256s=rendered_hashes,
        pdfinfo_sha256=executable_hashes["pdfinfo"],
        pdftotext_sha256=executable_hashes["pdftotext"],
        pdftoppm_sha256=executable_hashes["pdftoppm"],
        poppler_version=version,
        receipt_sha256=_digest(_canonical_json(body).encode()),
    )


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
    _source_policy_only: bool = False,
) -> CVConstraintReceipt | CandidateSourcePolicyReceipt:
    """Fail closed on forbidden CV content and candidate-specific invariants."""
    selected = policy or policy_for_candidate(candidate_name)
    if not _SHA256.fullmatch(source_id) or not _SHA256.fullmatch(cv_sha256):
        raise CVConstraintError("CV generation identities must be SHA-256")
    if _digest(cv_text.encode()) != cv_sha256:
        raise CVConstraintError("CV text differs from its retained hash")
    folded = _fold_display_text(cv_text)
    if re.search(
        r"(?mi)^\s*(?:.*\s[-|:]\s*)?(?:curriculum[ -]?vit(?:ae|æ)|c\.?\s*v\.?|resume)\s*$",
        folded,
    ):
        raise CVConstraintError("CV document labels are forbidden")
    work_rights = next((value for value in _WORK_RIGHTS if value in folded), None)
    if work_rights is not None:
        raise CVConstraintError("work-rights and visa declarations are forbidden in CVs")
    if _WORK_RIGHTS_PARAPHRASE.search(cv_text):
        raise CVConstraintError("work-rights and visa declarations are forbidden in CVs")
    if _REJECTION_SIGNAL.search(cv_text):
        raise CVConstraintError("volunteered rejection signals are forbidden in CVs")
    if _GENERIC_FILLER.search(_section_text(sections, "Professional Summary")):
        raise CVConstraintError("generic professional-summary filler is forbidden")

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
        if any(
            line == role
            or line.startswith(f"target role {role}")
            or re.match(rf"^{re.escape(role)}\b", line)
            for line in summary_lines
        ):
            raise CVConstraintError("target role cannot masquerade as current identity")

    education = _section_text(sections, "Education")
    if _DAY_MONTH_YEAR.search(education) or _NUMERIC_DAY_DATE.search(education):
        raise CVConstraintError("graduation dates must use month and year only")
    for heading in ("Skills", "Core Capabilities"):
        section_text = _section_text(sections, heading)
        if _FORMAT_INVENTORY.search(section_text):
            raise CVConstraintError(
                "formats, interchange syntax and storage engines cannot be listed as skills"
            )
        for line in sections.get(heading, ()):
            tool_count = len(_TOOL_TOKEN.findall(line))
            bridged = re.search(r"\b(?:using|with|through|across|via)\b", line, re.I)
            inventory_shape = len(re.findall(r"[,|;/]", line)) >= 2 or ":" in line
            if tool_count >= 2 and not _CAPABILITY_LANGUAGE.search(line) or (
                tool_count >= 3 and inventory_shape and not bridged
            ):
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
        dissertation_lines = tuple(
            line for line in sections.get("Education", ()) if "dissertation" in line.casefold()
        )
        if any(selected.required_dissertation_title not in line for line in dissertation_lines):
            raise CVConstraintError("generic or alternate dissertation wording is forbidden")
        if selected.required_capabilities_heading not in sections:
            raise CVConstraintError("professional capabilities section is absent")
        if "Projects" not in sections:
            raise CVConstraintError("verified projects section is required")
        if _STALE_OR_IRRELEVANT.search(cv_text):
            raise CVConstraintError("stale or irrelevant candidate detail is forbidden")
        if _IRRELEVANT_EXPERIENCE.search(_section_text(sections, "Experience")):
            raise CVConstraintError("irrelevant historic experience is forbidden")
        if re.search(r"\b2022\b", _section_text(sections, "Experience")):
            raise CVConstraintError("irrelevant historic experience is forbidden")
        if "wolverhampton" in folded:
            raise CVConstraintError("conflicting candidate location is forbidden")

    receipt_schema = (
        "jaa.candidate-source-policy-receipt.v1"
        if _source_policy_only
        else "jaa.cv-constraint-receipt.v1"
    )
    receipt_body = {
        "schema_version": receipt_schema,
        "source_id": source_id,
        "cv_sha256": cv_sha256,
        "policy_sha256": selected.policy_sha256,
        "passed": True,
        "release_authority": False,
    }
    receipt_type = (
        CandidateSourcePolicyReceipt if _source_policy_only else CVConstraintReceipt
    )
    return receipt_type(
        source_id=source_id,
        cv_sha256=cv_sha256,
        policy_sha256=selected.policy_sha256,
        receipt_sha256=_digest(_canonical_json(receipt_body).encode()),
    )


def validate_candidate_source_policy(
    **kwargs: object,
) -> CandidateSourcePolicyReceipt:
    """Run settled CV content policy without claiming rendered-artifact admission."""
    receipt = validate_generated_cv(**kwargs, _source_policy_only=True)
    if not isinstance(receipt, CandidateSourcePolicyReceipt):
        raise CVConstraintError("candidate source validation returned the wrong receipt")
    return receipt


__all__ = [
    "ARTIOM_GUTU_CV_POLICY",
    "BASE_CV_POLICY",
    "CVConstraintError",
    "CVConstraintReceipt",
    "CandidateSourcePolicyReceipt",
    "CVPopplerQualityReceipt",
    "CVPolicy",
    "policy_for_candidate",
    "validate_generated_cv",
    "validate_candidate_source_policy",
    "verify_poppler_cv_quality",
]
