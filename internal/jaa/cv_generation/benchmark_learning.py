"""Non-authoritative empirical CV benchmark diagnostics.

This boundary is separate from document quality: it owns an external corpus
manifest and structure/style measurements, never rendering, candidate facts,
or policy promotion. Corpus entries retain hashes and numeric features only;
exemplar prose is deliberately outside the contract.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Mapping

from career_automation.evidence_matching import content_hash

from .editorial_composition import CVEditorialDraft


MANIFEST_SCHEMA = "jaa.cv-benchmark-manifest.v1"
RECEIPT_SCHEMA = "jaa.cv-benchmark-diagnostic.v1"
FEATURE_NAMES = (
    "hierarchy",
    "evidence_density",
    "specificity",
    "readability",
    "ats_structure",
    "non_duplication",
    "role_relevance",
)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9+#.-]*")
_SPECIFIC = re.compile(
    r"\b(?:built|designed|developed|implemented|led|delivered|tested|"
    r"validated|reduced|increased|automated|architected)\b|\b\d[\d,.%+]*\b",
    re.IGNORECASE,
)
_STOP = frozenset(
    "a an and as at be by for from in into is it of on or that the to with".split()
)
_STANDARD_HEADINGS = frozenset(
    {"Professional Summary", "Core Capabilities", "Projects", "Experience", "Education", "Certifications"}
)


class CVBenchmarkError(ValueError):
    """Benchmark input or receipt is not admissible."""


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise CVBenchmarkError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CVBenchmarkError(f"{label} must be a trimmed non-empty string")
    return value


@dataclass(frozen=True)
class CVBenchmarkFeatures:
    hierarchy: int
    evidence_density: int
    specificity: int
    readability: int
    ats_structure: int
    non_duplication: int
    role_relevance: int

    def __post_init__(self) -> None:
        for name in FEATURE_NAMES:
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 10_000:
                raise CVBenchmarkError(f"benchmark feature {name} must be basis points")


@dataclass(frozen=True)
class CVBenchmarkEntry:
    exemplar_id: str
    source_sha256: str
    source_uri_sha256: str
    license_id: str
    provenance_sha256: str
    outcome_kind: str
    outcome_sha256: str
    features: CVBenchmarkFeatures
    jurisdiction: str = "UK"
    career_stage: str = "early-career"
    anonymized: bool = True

    def __post_init__(self) -> None:
        _required(self.exemplar_id, "benchmark exemplar ID")
        _required(self.license_id, "benchmark license")
        for value, label in (
            (self.source_sha256, "benchmark source hash"),
            (self.source_uri_sha256, "benchmark source URI hash"),
            (self.provenance_sha256, "benchmark provenance hash"),
            (self.outcome_sha256, "benchmark outcome hash"),
        ):
            _digest(value, label)
        if self.outcome_kind not in {"interview", "offer", "expert_review"}:
            raise CVBenchmarkError("benchmark outcome kind is unsupported")
        if self.jurisdiction != "UK" or self.career_stage != "early-career":
            raise CVBenchmarkError("benchmark cohort is outside the supported scope")
        if self.anonymized is not True:
            raise CVBenchmarkError("benchmark exemplars must be anonymized")
        self.features.__post_init__()


@dataclass(frozen=True)
class CVBenchmarkManifest:
    entries: tuple[CVBenchmarkEntry, ...]
    manifest_sha256: str
    schema_version: str = MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != MANIFEST_SCHEMA or not self.entries:
            raise CVBenchmarkError("benchmark manifest is unsupported or empty")
        if len({entry.exemplar_id for entry in self.entries}) != len(self.entries):
            raise CVBenchmarkError("benchmark manifest repeats an exemplar")
        for entry in self.entries:
            entry.__post_init__()
        _digest(self.manifest_sha256, "benchmark manifest hash")
        if self.manifest_sha256 != content_hash(self.document(include_identity=False)):
            raise CVBenchmarkError("benchmark manifest identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "entries": [asdict(entry) for entry in self.entries],
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["manifest_sha256"] = self.manifest_sha256
        return value


def build_benchmark_manifest(entries: tuple[CVBenchmarkEntry, ...]) -> CVBenchmarkManifest:
    values = {"entries": [asdict(entry) for entry in entries], "schema_version": MANIFEST_SCHEMA}
    return CVBenchmarkManifest(entries, content_hash(values))


def load_benchmark_manifest(path: str | Path) -> CVBenchmarkManifest:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if set(payload) != {"entries", "manifest_sha256", "schema_version"}:
        raise CVBenchmarkError("benchmark manifest contains unsupported fields")
    entries = []
    allowed = set(CVBenchmarkEntry.__dataclass_fields__)
    for raw in payload["entries"]:
        if set(raw) != allowed:
            raise CVBenchmarkError("benchmark entry contains unsupported fields")
        raw = dict(raw)
        raw["features"] = CVBenchmarkFeatures(**raw["features"])
        entries.append(CVBenchmarkEntry(**raw))
    return CVBenchmarkManifest(tuple(entries), payload["manifest_sha256"], payload["schema_version"])


@dataclass(frozen=True)
class CVBenchmarkDiagnosticReceipt:
    draft_sha256: str
    vacancy_sha256: str
    manifest_sha256: str
    candidate_features: CVBenchmarkFeatures
    benchmark_features: CVBenchmarkFeatures
    proposal_codes: tuple[str, ...]
    receipt_sha256: str
    release_authority: bool = False
    factual_authority: str = "candidate_evidence_only"
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        for value, label in ((self.draft_sha256, "draft hash"), (self.vacancy_sha256, "vacancy hash"), (self.manifest_sha256, "manifest hash"), (self.receipt_sha256, "receipt hash")):
            _digest(value, label)
        self.candidate_features.__post_init__()
        self.benchmark_features.__post_init__()
        if self.release_authority is not False or self.factual_authority != "candidate_evidence_only":
            raise CVBenchmarkError("benchmark diagnostics cannot grant factual or release authority")
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise CVBenchmarkError("benchmark receipt identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "benchmark_features": asdict(self.benchmark_features),
            "candidate_features": asdict(self.candidate_features),
            "draft_sha256": self.draft_sha256,
            "factual_authority": self.factual_authority,
            "manifest_sha256": self.manifest_sha256,
            "proposal_codes": list(self.proposal_codes),
            "release_authority": False,
            "schema_version": self.schema_version,
            "vacancy_sha256": self.vacancy_sha256,
        }
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value


def _words(text: str) -> tuple[str, ...]:
    return tuple(word.casefold() for word in _WORD.findall(text))


def extract_cv_features(draft: CVEditorialDraft, listing_text: str) -> CVBenchmarkFeatures:
    draft.__post_init__()
    atoms = tuple(atom for section in draft.sections for atom in section.atoms)
    facts = tuple(atom for atom in atoms if atom.source_kind == "approved_claim")
    texts = tuple(atom.text.strip() for atom in atoms)
    headings = tuple(section.heading for section in draft.sections)
    hierarchy = 10_000 if headings[0] == "Professional Summary" and set(headings) <= _STANDARD_HEADINGS else 0
    evidence_density = round(10_000 * len(facts) / len(atoms))
    specificity = round(10_000 * sum(bool(_SPECIFIC.search(atom.text)) for atom in facts) / len(facts))
    average_words = mean(len(_words(text)) for text in texts)
    readability = max(0, 10_000 - round(abs(average_words - 18) * 500))
    ats_structure = 10_000 if all(heading in _STANDARD_HEADINGS for heading in headings) else 0
    non_duplication = round(10_000 * len({text.casefold() for text in texts}) / len(texts))
    listing_words = {word for word in _words(listing_text) if word not in _STOP and len(word) > 2}
    draft_words = {word for text in texts for word in _words(text) if word not in _STOP and len(word) > 2}
    role_relevance = round(10_000 * len(listing_words & draft_words) / len(listing_words)) if listing_words else 0
    return CVBenchmarkFeatures(hierarchy, evidence_density, specificity, readability, ats_structure, non_duplication, role_relevance)


def evaluate_cv_benchmark(*, draft: CVEditorialDraft, listing_text: str, vacancy_sha256: str, manifest: CVBenchmarkManifest) -> CVBenchmarkDiagnosticReceipt:
    manifest.__post_init__()
    _digest(vacancy_sha256, "vacancy hash")
    candidate = extract_cv_features(draft, listing_text)
    target = CVBenchmarkFeatures(**{
        name: round(mean(getattr(entry.features, name) for entry in manifest.entries))
        for name in FEATURE_NAMES
    })
    proposals = tuple(f"improve_{name}" for name in FEATURE_NAMES if getattr(candidate, name) < getattr(target, name))
    values = {
        "benchmark_features": asdict(target), "candidate_features": asdict(candidate),
        "draft_sha256": draft.draft_sha256, "factual_authority": "candidate_evidence_only",
        "manifest_sha256": manifest.manifest_sha256, "proposal_codes": list(proposals),
        "release_authority": False, "schema_version": RECEIPT_SCHEMA, "vacancy_sha256": vacancy_sha256,
    }
    return CVBenchmarkDiagnosticReceipt(
        draft.draft_sha256, vacancy_sha256, manifest.manifest_sha256, candidate, target,
        proposals, content_hash(values)
    )


__all__ = [
    "CVBenchmarkDiagnosticReceipt", "CVBenchmarkEntry", "CVBenchmarkError",
    "CVBenchmarkFeatures", "CVBenchmarkManifest", "build_benchmark_manifest",
    "evaluate_cv_benchmark", "extract_cv_features", "load_benchmark_manifest",
]
