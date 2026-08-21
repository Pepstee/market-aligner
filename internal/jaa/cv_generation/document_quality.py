"""Deterministic post-render document quality verification.

Rendering and external-document assurance own construction, byte identity and
outward-content safety.  This module owns the later runtime check against an
independent Poppler toolchain: page geometry, ATS reading order, text bounds,
font hierarchy, duplicate prose and raster identity.  Its receipt is evidence
for a later publication decision, never release authority or a visual opinion.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from career_automation.evidence_matching import content_hash
from career_automation.rendering import (
    CV_SECTION_HEADINGS,
    ApplicationArtifacts,
    PdfArtifact,
    verify_application_artifacts,
)


QUALITY_SCHEMA = "jaa.cv-document-quality-receipt.v1"
QUALITY_POLICY_SCHEMA = "jaa.cv-document-quality-policy.v1"
POPPLER_TOOLS = ("pdfinfo", "pdffonts", "pdftotext", "pdftoppm")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TABLE_MARKERS = (b"/Table", b"/TR", b"/TH", b"/TD")
_FONT_COMMAND = re.compile(rb"/(F[12])\s+([0-9]+(?:\.[0-9]+)?)\s+Tf")
_A4_WIDTH = 595.0
_A4_HEIGHT = 842.0
_GEOMETRY_TOLERANCE = 1.0
_MINIMUM_MARGIN = 36.0


QUALITY_POLICY_SHA256 = content_hash(
    {
        "schema_version": QUALITY_POLICY_SCHEMA,
        "page_sizes": {"cv": (1, 2), "cover_letter": (1,)},
        "a4_points": (_A4_WIDTH, _A4_HEIGHT),
        "geometry_tolerance_points": _GEOMETRY_TOLERANCE,
        "minimum_text_margin_points": _MINIMUM_MARGIN,
        "ats_order": "poppler-layout-lines-equal-rendered-lines",
        "font_hierarchy": "name-16-bold;cv-heading-11-bold;body-10-regular",
        "forbidden_structure": ("image", "table", "form", "annotation"),
        "duplicate_prose": "exact-normalized-logical-line-at-least-24-characters",
        "raster": "poppler-png-144-dpi-sha256-per-page",
        "visual_judgement": "separate-required",
    }
)


class DocumentQualityError(ValueError):
    """A rendered document cannot produce a deterministic quality receipt."""


@dataclass(frozen=True)
class PopplerRuntime:
    version: str
    tool_paths: tuple[tuple[str, str], ...]
    tool_sha256: tuple[tuple[str, str], ...]
    runtime_sha256: str
    library_directory: str | None = None
    tool_descriptors: tuple[tuple[str, int], ...] = ()
    preload_paths: tuple[str, ...] = ()
    preload_descriptors: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if not self.version.strip() or set(dict(self.tool_paths)) != set(POPPLER_TOOLS):
            raise DocumentQualityError("Poppler runtime is incomplete")
        if set(dict(self.tool_sha256)) != set(POPPLER_TOOLS):
            raise DocumentQualityError("Poppler runtime hashes are incomplete")
        if self.tool_descriptors and set(dict(self.tool_descriptors)) != set(POPPLER_TOOLS):
            raise DocumentQualityError("Poppler runtime descriptors are incomplete")
        if len(self.preload_paths) != len(self.preload_descriptors):
            raise DocumentQualityError("Poppler runtime preload lease is incomplete")
        for value in (*dict(self.tool_sha256).values(), self.runtime_sha256):
            if not _SHA256.fullmatch(value):
                raise DocumentQualityError("Poppler runtime identity is invalid")

    def document(self) -> dict[str, object]:
        return {
            "version": self.version,
            "tool_sha256": dict(self.tool_sha256),
            "runtime_sha256": self.runtime_sha256,
        }


@dataclass(frozen=True)
class PdfQualityResult:
    document_kind: str
    pdf_sha256: str
    page_count: int
    page_size_points: tuple[float, float]
    minimum_margin_points: float
    ats_text_sha256: str
    raster_sha256: tuple[str, ...]
    raster_set_sha256: str
    font_hierarchy: tuple[tuple[str, float], ...]
    duplicate_prose: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.document_kind not in {"cv", "cover_letter"}:
            raise DocumentQualityError("quality result document kind is unsupported")
        if self.page_count < 1 or len(self.raster_sha256) != self.page_count:
            raise DocumentQualityError("quality result page identity is inconsistent")
        for value in (self.pdf_sha256, self.ats_text_sha256, self.raster_set_sha256, *self.raster_sha256):
            if not _SHA256.fullmatch(value):
                raise DocumentQualityError("quality result hash is invalid")
        if self.duplicate_prose:
            raise DocumentQualityError("quality result cannot retain duplicate prose")

    def document(self) -> dict[str, object]:
        return {
            "document_kind": self.document_kind,
            "pdf_sha256": self.pdf_sha256,
            "page_count": self.page_count,
            "page_size_points": self.page_size_points,
            "minimum_margin_points": self.minimum_margin_points,
            "ats_text_sha256": self.ats_text_sha256,
            "raster_sha256": self.raster_sha256,
            "raster_set_sha256": self.raster_set_sha256,
            "font_hierarchy": self.font_hierarchy,
            "duplicate_prose": self.duplicate_prose,
        }


@dataclass(frozen=True)
class DocumentQualityReceipt:
    artifact_set_sha256: str
    poppler_runtime_sha256: str
    results: tuple[PdfQualityResult, ...]
    policy_sha256: str
    receipt_sha256: str
    release_authority: bool = False
    visual_judgement: str = "not_performed"
    requires_visual_review: bool = True
    schema_version: str = QUALITY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != QUALITY_SCHEMA or self.policy_sha256 != QUALITY_POLICY_SHA256:
            raise DocumentQualityError("document-quality policy is unsupported")
        for value in (self.artifact_set_sha256, self.poppler_runtime_sha256, self.receipt_sha256):
            if not _SHA256.fullmatch(value):
                raise DocumentQualityError("document-quality receipt hash is invalid")
        if tuple(row.document_kind for row in self.results) != ("cv", "cover_letter"):
            raise DocumentQualityError("document-quality receipt is incomplete")
        for row in self.results:
            row.__post_init__()
        if self.release_authority is not False:
            raise DocumentQualityError("document quality cannot grant release authority")
        if self.visual_judgement != "not_performed" or self.requires_visual_review is not True:
            raise DocumentQualityError("deterministic quality cannot claim visual judgement")
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise DocumentQualityError("document-quality receipt identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "artifact_set_sha256": self.artifact_set_sha256,
            "poppler_runtime_sha256": self.poppler_runtime_sha256,
            "results": tuple(row.document() for row in self.results),
            "policy_sha256": self.policy_sha256,
            "release_authority": False,
            "visual_judgement": "not_performed",
            "requires_visual_review": True,
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value


def _candidate_bin_directories(explicit: str | Path | None) -> Iterable[Path]:
    if explicit is not None:
        yield Path(explicit)
        return
    configured = os.environ.get("JAA_POPPLER_BIN")
    if configured:
        yield Path(configured)
    discovered = shutil.which("pdftoppm")
    if discovered:
        yield Path(discovered).parent
    yield Path.home() / ".local" / "poppler" / "usr" / "bin"


def resolve_poppler_runtime(bin_directory: str | Path | None = None) -> PopplerRuntime:
    """Resolve one complete Poppler installation or fail closed."""
    selected: Path | None = None
    for candidate in _candidate_bin_directories(bin_directory):
        if all((candidate / tool).is_file() and os.access(candidate / tool, os.X_OK) for tool in POPPLER_TOOLS):
            selected = candidate.resolve()
            break
    if selected is None:
        raise DocumentQualityError("Poppler runtime is required but unavailable")
    prefix = selected.parent
    library = prefix / "lib" / "x86_64-linux-gnu"
    library_directory = str(library) if library.is_dir() else None
    paths = tuple((tool, str(selected / tool)) for tool in POPPLER_TOOLS)
    hashes = tuple(
        (tool, hashlib.sha256(Path(path).read_bytes()).hexdigest())
        for tool, path in paths
    )
    environment = _runtime_environment(library_directory)
    completed = subprocess.run(
        (dict(paths)["pdftoppm"], "-v"),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=environment,
    )
    version_output = (completed.stderr or completed.stdout).splitlines()
    # Poppler conventionally returns 99 for the informational ``-v`` path.
    if completed.returncode not in {0, 99} or not any(
        "pdftoppm version" in line for line in version_output
    ):
        raise DocumentQualityError("Poppler runtime cannot execute")
    version = next(line.strip() for line in version_output if "pdftoppm version" in line)
    runtime_sha256 = content_hash({"version": version, "tool_sha256": dict(hashes)})
    return PopplerRuntime(version, paths, hashes, runtime_sha256, library_directory)


def pinned_poppler_runtime(
    descriptors: Mapping[str, int],
    expected_sha256: Mapping[str, str],
    *,
    library_descriptors: Mapping[str, int] | None = None,
    expected_library_sha256: Mapping[str, str] | None = None,
) -> PopplerRuntime:
    """Build a runtime that consumes only already-open executable descriptors."""
    if set(descriptors) != set(POPPLER_TOOLS) or set(expected_sha256) != set(POPPLER_TOOLS):
        raise DocumentQualityError("pinned Poppler lease is incomplete")
    paths: list[tuple[str, str]] = []
    hashes: list[tuple[str, str]] = []
    for tool in POPPLER_TOOLS:
        descriptor = descriptors[tool]
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & stat.S_IXUSR:
            raise DocumentQualityError("pinned Poppler executable is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if digest.hexdigest() != expected_sha256[tool]:
            raise DocumentQualityError("pinned Poppler executable hash differs")
        paths.append((tool, f"/proc/self/fd/{descriptor}"))
        hashes.append((tool, digest.hexdigest()))
    if (library_descriptors is None) != (expected_library_sha256 is None):
        raise DocumentQualityError("pinned Poppler library lease is incomplete")
    library_paths: list[str] = []
    library_hashes: list[tuple[str, str]] = []
    if library_descriptors is not None and expected_library_sha256 is not None:
        if not library_descriptors or set(library_descriptors) != set(expected_library_sha256):
            raise DocumentQualityError("pinned Poppler library lease is incomplete")
        for name in sorted(library_descriptors):
            descriptor = library_descriptors[name]
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise DocumentQualityError("pinned Poppler library is invalid")
            os.lseek(descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if digest.hexdigest() != expected_library_sha256[name]:
                raise DocumentQualityError("pinned Poppler library hash differs")
            library_paths.append(f"/proc/self/fd/{descriptor}")
            library_hashes.append((name, digest.hexdigest()))
    pass_descriptors = tuple(descriptors.values()) + tuple(
        () if library_descriptors is None else library_descriptors.values()
    )
    completed = subprocess.run(
        (dict(paths)["pdftoppm"], "-v"),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=_runtime_environment(None, tuple(library_paths)),
        pass_fds=pass_descriptors,
    )
    version_output = (completed.stderr or completed.stdout).splitlines()
    if completed.returncode not in {0, 99} or not any(
        "pdftoppm version" in line for line in version_output
    ):
        raise DocumentQualityError("pinned Poppler runtime cannot execute")
    version = next(line.strip() for line in version_output if "pdftoppm version" in line)
    runtime_identity: dict[str, object] = {
        "version": version,
        "tool_sha256": dict(hashes),
    }
    if library_hashes:
        runtime_identity["preload_sha256"] = dict(library_hashes)
    runtime_sha256 = content_hash(runtime_identity)
    return PopplerRuntime(
        version,
        tuple(paths),
        tuple(hashes),
        runtime_sha256,
        None,
        tuple((tool, descriptors[tool]) for tool in POPPLER_TOOLS),
        tuple(library_paths),
        tuple(() if library_descriptors is None else library_descriptors.values()),
    )


def _runtime_environment(
    library_directory: str | None,
    preload_paths: tuple[str, ...] = (),
) -> dict[str, str]:
    environment = dict(os.environ)
    if library_directory:
        existing = environment.get("LD_LIBRARY_PATH")
        environment["LD_LIBRARY_PATH"] = (
            library_directory if not existing else f"{library_directory}:{existing}"
        )
    if preload_paths:
        environment["LD_PRELOAD"] = ":".join(preload_paths)
    return environment


def _run(runtime: PopplerRuntime, tool: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        (dict(runtime.tool_paths)[tool], *arguments),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=_runtime_environment(runtime.library_directory, runtime.preload_paths),
        pass_fds=(
            tuple(dict(runtime.tool_descriptors).values())
            + runtime.preload_descriptors
        ),
    )
    if completed.returncode != 0:
        raise DocumentQualityError(f"Poppler {tool} failed")
    return completed


def _normalized_lines(text: str) -> tuple[str, ...]:
    return tuple(" ".join(line.split()) for line in text.splitlines() if line.strip())


def _duplicate_prose(text: str) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for line in _normalized_lines(text):
        normalized = re.sub(r"^[-•]\s*", "", line).casefold()
        if len(normalized) < 24 or line in CV_SECTION_HEADINGS:
            continue
        if normalized in seen:
            duplicates.add(normalized)
        seen.add(normalized)
    return tuple(sorted(duplicates))


def _font_hierarchy(artifact: PdfArtifact) -> tuple[tuple[str, float], ...]:
    commands = tuple((font.decode(), float(size)) for font, size in _FONT_COMMAND.findall(artifact.pdf_bytes))
    sizes = set(commands)
    required = {("F2", 16.0), ("F1", 10.0)}
    if artifact.document_kind == "cv":
        required.add(("F2", 11.0))
    if not required.issubset(sizes) or not (16.0 > 11.0 > 10.0):
        raise DocumentQualityError("PDF font hierarchy is invalid")
    return tuple(sorted(sizes, key=lambda item: (-item[1], item[0])))


def _parse_pdfinfo(output: str, artifact: PdfArtifact) -> tuple[float, float]:
    values = {}
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    if values.get("Pages") != str(artifact.page_count):
        raise DocumentQualityError("Poppler page count differs from the artifact")
    if values.get("Encrypted") != "no" or values.get("Form") != "none" or values.get("JavaScript") != "no":
        raise DocumentQualityError("PDF contains forbidden active or form content")
    match = re.match(r"([0-9.]+)\s+x\s+([0-9.]+)\s+pts", values.get("Page size", ""))
    if match is None:
        raise DocumentQualityError("Poppler did not report page geometry")
    width, height = (float(match.group(1)), float(match.group(2)))
    if abs(width - _A4_WIDTH) > _GEOMETRY_TOLERANCE or abs(height - _A4_HEIGHT) > _GEOMETRY_TOLERANCE:
        raise DocumentQualityError("PDF page size is not A4")
    return width, height


def _minimum_margin(bbox_path: Path, page_size: tuple[float, float], expected_pages: int) -> float:
    root = ET.parse(bbox_path).getroot()
    pages = root.findall(".//{*}page")
    if len(pages) != expected_pages:
        raise DocumentQualityError("Poppler bounding-box page count differs")
    margins: list[float] = []
    for page in pages:
        width = float(page.attrib["width"])
        height = float(page.attrib["height"])
        if abs(width - page_size[0]) > _GEOMETRY_TOLERANCE or abs(height - page_size[1]) > _GEOMETRY_TOLERANCE:
            raise DocumentQualityError("Poppler page geometries differ")
        words = page.findall(".//{*}word")
        if not words:
            raise DocumentQualityError("PDF page has no visible text bounds")
        for word in words:
            x_min = float(word.attrib["xMin"])
            x_max = float(word.attrib["xMax"])
            y_min = float(word.attrib["yMin"])
            y_max = float(word.attrib["yMax"])
            if x_min < 0 or y_min < 0 or x_max > width or y_max > height or x_max <= x_min or y_max <= y_min:
                raise DocumentQualityError("PDF text is clipped or outside its page")
            margins.extend((x_min, width - x_max, y_min, height - y_max))
    minimum = min(margins)
    if minimum < _MINIMUM_MARGIN:
        raise DocumentQualityError("PDF text violates the minimum page margin")
    return minimum


def _verify_pdf(
    artifact: PdfArtifact,
    editable_text: str,
    runtime: PopplerRuntime,
    directory: Path,
) -> PdfQualityResult:
    if any(marker in artifact.pdf_bytes for marker in _TABLE_MARKERS):
        raise DocumentQualityError("PDF contains forbidden table structure")
    duplicates = _duplicate_prose(editable_text)
    if duplicates:
        raise DocumentQualityError("document contains exact duplicate prose")
    pdf_path = directory / f"{artifact.document_kind}.pdf"
    pdf_path.write_bytes(artifact.pdf_bytes)
    info = _run(runtime, "pdfinfo", str(pdf_path)).stdout
    page_size = _parse_pdfinfo(info, artifact)
    layout_path = directory / f"{artifact.document_kind}.txt"
    _run(runtime, "pdftotext", "-layout", str(pdf_path), str(layout_path))
    poppler_text = layout_path.read_text(encoding="utf-8")
    expected_lines = tuple(line for page in artifact.rendered_lines for line in page if line.strip())
    if _normalized_lines(poppler_text) != expected_lines:
        raise DocumentQualityError("Poppler ATS text order differs from rendered order")
    bbox_path = directory / f"{artifact.document_kind}.html"
    _run(runtime, "pdftotext", "-bbox-layout", str(pdf_path), str(bbox_path))
    minimum_margin = _minimum_margin(bbox_path, page_size, artifact.page_count)
    raster_prefix = directory / f"{artifact.document_kind}-page"
    _run(runtime, "pdftoppm", "-png", "-r", "144", str(pdf_path), str(raster_prefix))
    raster_paths = sorted(directory.glob(f"{artifact.document_kind}-page-*.png"))
    if len(raster_paths) != artifact.page_count:
        raise DocumentQualityError("Poppler raster page count differs")
    raster_hashes = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in raster_paths)
    return PdfQualityResult(
        document_kind=artifact.document_kind,
        pdf_sha256=artifact.pdf_sha256,
        page_count=artifact.page_count,
        page_size_points=page_size,
        minimum_margin_points=round(minimum_margin, 3),
        ats_text_sha256=hashlib.sha256(poppler_text.encode()).hexdigest(),
        raster_sha256=raster_hashes,
        raster_set_sha256=content_hash(raster_hashes),
        font_hierarchy=_font_hierarchy(artifact),
    )


def verify_document_quality(
    artifacts: ApplicationArtifacts,
    *,
    poppler_bin_directory: str | Path | None = None,
    poppler_runtime: PopplerRuntime | None = None,
) -> DocumentQualityReceipt:
    """Verify both rendered PDFs with Poppler and emit a non-release receipt."""
    verify_application_artifacts(artifacts)
    runtime = poppler_runtime or resolve_poppler_runtime(poppler_bin_directory)
    runtime.__post_init__()
    with tempfile.TemporaryDirectory(prefix="jaa-cv-quality-") as temporary:
        directory = Path(temporary)
        results = (
            _verify_pdf(artifacts.cv_pdf, artifacts.editable.cv_text, runtime, directory),
            _verify_pdf(
                artifacts.cover_letter_pdf,
                artifacts.editable.cover_letter_text,
                runtime,
                directory,
            ),
        )
    values = {
        "artifact_set_sha256": artifacts.artifact_set_sha256,
        "poppler_runtime_sha256": runtime.runtime_sha256,
        "results": tuple(row.document() for row in results),
        "policy_sha256": QUALITY_POLICY_SHA256,
        "release_authority": False,
        "visual_judgement": "not_performed",
        "requires_visual_review": True,
        "schema_version": QUALITY_SCHEMA,
    }
    return DocumentQualityReceipt(
        artifact_set_sha256=artifacts.artifact_set_sha256,
        poppler_runtime_sha256=runtime.runtime_sha256,
        results=results,
        policy_sha256=QUALITY_POLICY_SHA256,
        receipt_sha256=content_hash(values),
    )


__all__ = [
    "DocumentQualityError",
    "DocumentQualityReceipt",
    "PdfQualityResult",
    "PopplerRuntime",
    "QUALITY_POLICY_SHA256",
    "resolve_poppler_runtime",
    "pinned_poppler_runtime",
    "verify_document_quality",
]
