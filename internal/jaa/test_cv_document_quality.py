from __future__ import annotations

from career_automation.form_answers import form_answers_bytes

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cv_generation import document_quality as quality
from career_automation.rendering import (
    ApplicationArtifacts,
    EditableArtifacts,
    PdfLineBox,
    RENDERER_POLICY_SHA256,
    _artifact,
)
from cv_generation.document_quality import (
    DocumentQualityError,
    _duplicate_prose,
    _expected_lines,
    _font_hierarchy,
    _minimum_margin,
    _parse_pdfinfo,
    pinned_poppler_runtime,
    resolve_poppler_runtime,
    verify_document_quality,
)


def test_pinned_poppler_preloads_exact_library_descriptors(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    descriptors: dict[str, int] = {}
    hashes: dict[str, str] = {}
    for name in quality.POPPLER_TOOLS:
        path = tmp_path / name
        path.write_bytes(name.encode())
        path.chmod(0o755)
        descriptors[name] = os.open(path, os.O_RDONLY)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    library_path = tmp_path / "libpoppler.so.156.0.0"
    library_path.write_bytes(b"exact library")
    library_path.chmod(0o644)
    library_descriptor = os.open(library_path, os.O_RDONLY)
    calls: list[dict[str, object]] = []

    def run(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="pdftoppm version 26.01.0\n",
        )

    monkeypatch.setattr(quality.subprocess, "run", run)
    try:
        runtime = pinned_poppler_runtime(
            descriptors,
            hashes,
            library_descriptors={"libpoppler.so.156.0.0": library_descriptor},
            expected_library_sha256={
                "libpoppler.so.156.0.0": hashlib.sha256(
                    library_path.read_bytes()
                ).hexdigest()
            },
        )
        assert runtime.preload_paths == (f"/proc/self/fd/{library_descriptor}",)
        assert runtime.preload_descriptors == (library_descriptor,)
        assert calls[0]["env"]["LD_PRELOAD"] == runtime.preload_paths[0]
        assert set(calls[0]["pass_fds"]) == {*descriptors.values(), library_descriptor}
    finally:
        for descriptor in (*descriptors.values(), library_descriptor):
            os.close(descriptor)


def test_pinned_poppler_rejects_library_hash_substitution(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    descriptors: dict[str, int] = {}
    hashes: dict[str, str] = {}
    for name in quality.POPPLER_TOOLS:
        path = tmp_path / name
        path.write_bytes(name.encode())
        path.chmod(0o755)
        descriptors[name] = os.open(path, os.O_RDONLY)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    library_path = tmp_path / "libpoppler.so.156.0.0"
    library_path.write_bytes(b"substituted library")
    library_descriptor = os.open(library_path, os.O_RDONLY)
    monkeypatch.setattr(
        quality.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("transport ran after library substitution"),
    )
    try:
        with pytest.raises(DocumentQualityError, match="library hash differs"):
            pinned_poppler_runtime(
                descriptors,
                hashes,
                library_descriptors={"libpoppler.so.156.0.0": library_descriptor},
                expected_library_sha256={"libpoppler.so.156.0.0": "0" * 64},
            )
    finally:
        for descriptor in (*descriptors.values(), library_descriptor):
            os.close(descriptor)


def test_poppler_failure_output_never_echoes_protected_content(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    canary = "PROTECTED-CANDIDATE-CANARY-641dd08ace"
    runtime = quality.PopplerRuntime(
        version="pdftoppm version test",
        tool_paths=tuple((tool, f"/test/{tool}") for tool in quality.POPPLER_TOOLS),
        tool_sha256=tuple((tool, "a" * 64) for tool in quality.POPPLER_TOOLS),
        runtime_sha256="b" * 64,
    )
    monkeypatch.setattr(
        quality.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout=canary,
            stderr=canary,
        ),
    )

    with pytest.raises(DocumentQualityError, match="Poppler pdfinfo failed") as raised:
        quality._run(runtime, "pdfinfo", "/private/candidate/cv.pdf")

    captured = capsys.readouterr()
    assert canary not in str(raised.value)
    assert canary not in captured.out
    assert canary not in captured.err


def _clean_artifacts() -> ApplicationArtifacts:
    cv_text = """Alex Example
alex@example.test
+44 7700 900123
London

Professional Summary
- Delivered reliable services with independently verified evidence.

Core Capabilities
- Designed deterministic workflow automation around bounded authority.

Projects
- Built an evidence-linked application composition pipeline.
"""
    letter_text = """Alex Example
alex@example.test
+44 7700 900123
London
Software Engineer
Example Ltd

I am applying because the role matches my tested automation work.

My project evidence demonstrates reliable delivery and careful validation.

Example Ltd's documented service focus makes the work particularly relevant.

I would welcome the opportunity to discuss the engineering challenges.
"""
    answers = ""
    editable = EditableArtifacts(
        cv_text,
        letter_text,
        answers,
        hashlib.sha256(cv_text.encode()).hexdigest(),
        hashlib.sha256(letter_text.encode()).hexdigest(),
        hashlib.sha256(form_answers_bytes((), allow_empty=True)).hexdigest(),
    )

    def box(
        text: str, baseline: float, size: float, *, bold: bool = False
    ) -> PdfLineBox:
        return PdfLineBox(
            text=text,
            x=50.0,
            baseline_y=baseline,
            width=min(470.0, len(text) * size * 0.52),
            font_size=size,
            font_name="Helvetica-Bold" if bold else "Helvetica",
            role="fixture",
            color=(0.1, 0.12, 0.15),
        )

    cv_lines = tuple(line for line in cv_text.splitlines() if line)
    cv_layout = (
        tuple(
            box(
                line,
                790.0 - (index * 24.0),
                16.0
                if index == 0
                else 11.0
                if line in {"Professional Summary", "Core Capabilities", "Projects"}
                else 10.0,
                bold=index == 0
                or line in {"Professional Summary", "Core Capabilities", "Projects"},
            )
            for index, line in enumerate(cv_lines)
        ),
    )
    letter_lines = tuple(line for line in letter_text.splitlines() if line)
    letter_layout = (
        tuple(
            box(
                line,
                790.0 - (index * 24.0),
                16.0 if index == 0 else 10.0,
                bold=index == 0,
            )
            for index, line in enumerate(letter_lines)
        ),
    )
    cv = _artifact("cv", cv_layout)
    letter = _artifact("cover_letter", letter_layout)
    source_id = "a" * 64
    artifact_set = hashlib.sha256(
        "\n".join(
            (
                source_id,
                RENDERER_POLICY_SHA256,
                editable.cv_sha256,
                editable.cover_letter_sha256,
                editable.answers_sha256,
                cv.pdf_sha256,
                cv.extracted_text_sha256,
                letter.pdf_sha256,
                letter.extracted_text_sha256,
            )
        ).encode()
    ).hexdigest()
    return ApplicationArtifacts(source_id, editable, cv, letter, artifact_set)


def _rehash_editable(
    artifacts: ApplicationArtifacts, editable: EditableArtifacts
) -> ApplicationArtifacts:
    artifact_set = hashlib.sha256(
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
        ).encode()
    ).hexdigest()
    return replace(artifacts, editable=editable, artifact_set_sha256=artifact_set)


def test_real_poppler_quality_gate_records_geometry_order_and_rasters() -> None:
    receipt = verify_document_quality(_clean_artifacts())

    assert receipt.release_authority is False
    assert receipt.visual_judgement == "not_performed"
    assert receipt.requires_visual_review is True
    assert [row.document_kind for row in receipt.results] == ["cv", "cover_letter"]
    assert all(row.page_size_points == (595.0, 842.0) for row in receipt.results)
    assert all(row.minimum_margin_points >= 36.0 for row in receipt.results)
    assert all(len(row.raster_sha256) == row.page_count for row in receipt.results)
    assert receipt == verify_document_quality(_clean_artifacts())


def test_ats_order_equivalence_squeezes_bullet_continuation_indent() -> None:
    rendered = (
        "Professional Summary",
        "\u2022 Delivered reliable services with independently verified",
        "  evidence across multiple regulated regions",
    )
    artifact = SimpleNamespace(rendered_lines=(rendered,))
    poppler_layout_output = (
        "Professional Summary\n"
        "\u2022 Delivered reliable services with independently verified\n"
        "evidence across multiple regulated regions\n"
        "\f\n"
    )
    assert _expected_lines(artifact) == quality._normalized_lines(
        poppler_layout_output
    )
    raw_expected = tuple(line for line in rendered if line.strip())
    assert raw_expected != quality._normalized_lines(poppler_layout_output)


def _wrapped_bullet_artifacts() -> ApplicationArtifacts:
    cv_text = """Alex Example
Professional Summary
\u2022 Delivered reliable services with independently verified
  evidence across multiple regulated regions
"""
    letter_text = """Alex Example
alex@example.test
+44 7700 900123
London
Software Engineer
Example Ltd

I am applying because the role matches my tested automation work.
"""
    editable = EditableArtifacts(
        cv_text,
        letter_text,
        "",
        hashlib.sha256(cv_text.encode()).hexdigest(),
        hashlib.sha256(letter_text.encode()).hexdigest(),
        hashlib.sha256(form_answers_bytes((), allow_empty=True)).hexdigest(),
    )

    def box(
        text: str, baseline: float, size: float, *, bold: bool = False
    ) -> PdfLineBox:
        return PdfLineBox(
            text=text,
            x=50.0,
            baseline_y=baseline,
            width=min(470.0, len(text) * size * 0.52),
            font_size=size,
            font_name="Helvetica-Bold" if bold else "Helvetica",
            role="fixture",
            color=(0.1, 0.12, 0.15),
        )

    cv_lines = tuple(line for line in cv_text.splitlines() if line)
    cv_layout = (
        tuple(
            box(
                line,
                790.0 - (index * 24.0),
                16.0
                if index == 0
                else 11.0
                if line == "Professional Summary"
                else 10.0,
                bold=index == 0 or line == "Professional Summary",
            )
            for index, line in enumerate(cv_lines)
        ),
    )
    letter_lines = tuple(line for line in letter_text.splitlines() if line)
    letter_layout = (
        tuple(
            box(
                line,
                790.0 - (index * 24.0),
                16.0 if index == 0 else 10.0,
                bold=index == 0,
            )
            for index, line in enumerate(letter_lines)
        ),
    )
    cv = _artifact("cv", cv_layout)
    letter = _artifact("cover_letter", letter_layout)
    assert any(line.startswith("  ") for page in cv.rendered_lines for line in page)
    source_id = "a" * 64
    artifact_set = hashlib.sha256(
        "\n".join(
            (
                source_id,
                RENDERER_POLICY_SHA256,
                editable.cv_sha256,
                editable.cover_letter_sha256,
                editable.answers_sha256,
                cv.pdf_sha256,
                cv.extracted_text_sha256,
                letter.pdf_sha256,
                letter.extracted_text_sha256,
            )
        ).encode()
    ).hexdigest()
    return ApplicationArtifacts(source_id, editable, cv, letter, artifact_set)


def test_real_poppler_quality_gate_accepts_wrapped_bullet_continuation() -> None:
    receipt = verify_document_quality(_wrapped_bullet_artifacts())

    assert [row.document_kind for row in receipt.results] == ["cv", "cover_letter"]
    assert receipt == verify_document_quality(_wrapped_bullet_artifacts())


def _distinct_adjacent_nonblank_pair(lines: list[str]) -> tuple[int, int]:
    nonblank = [index for index, line in enumerate(lines) if line.strip()]
    for position in range(len(nonblank) - 1):
        first, second = nonblank[position], nonblank[position + 1]
        if quality._normalized_lines(lines[first]) != quality._normalized_lines(lines[second]):
            return first, second
    pytest.fail("baseline synthetic cv.txt lacks distinct adjacent nonblank lines")


def _first_nonblank_index(lines: list[str]) -> int:
    for index, line in enumerate(lines):
        if line.strip():
            return index
    pytest.fail("baseline synthetic cv.txt has no nonblank lines")


def _swap_adjacent_distinct_lines(text: str) -> str:
    lines = text.splitlines()
    first, second = _distinct_adjacent_nonblank_pair(lines)
    lines[first], lines[second] = lines[second], lines[first]
    return "\n".join(lines) + "\n"


def _drop_nonblank_line(text: str) -> str:
    lines = text.splitlines()
    del lines[_first_nonblank_index(lines)]
    return "\n".join(lines) + "\n"


def _duplicate_nonblank_line(text: str) -> str:
    lines = text.splitlines()
    target = _first_nonblank_index(lines)
    lines.insert(target + 1, lines[target])
    return "\n".join(lines) + "\n"


def _change_line_punctuation(text: str) -> str:
    lines = text.splitlines()
    target = _first_nonblank_index(lines)
    stripped = lines[target].rstrip()
    lines[target] = stripped + "," if stripped.endswith(".") else stripped + "."
    return "\n".join(lines) + "\n"


def _join_adjacent_distinct_lines(text: str) -> str:
    lines = text.splitlines()
    first, second = _distinct_adjacent_nonblank_pair(lines)
    lines[first : second + 1] = [lines[first].strip() + " " + lines[second].strip()]
    return "\n".join(lines) + "\n"


def _layout_mutating_run(calls: list[tuple[str, tuple[str, ...]]], mutate):
    original_run = quality._run

    def recording_run(runtime, tool, *arguments):
        result = original_run(runtime, tool, *arguments)
        calls.append((tool, arguments))
        if tool == "pdftotext" and "-layout" in arguments:
            text_path = Path(arguments[-1])
            baseline_text = text_path.read_text(encoding="utf-8")
            mutated_text = mutate(baseline_text)
            assert quality._normalized_lines(mutated_text) != quality._normalized_lines(
                baseline_text
            ), "mutation was vacuous: normalized Poppler text unchanged"
            text_path.write_text(mutated_text, encoding="utf-8")
        return result

    return recording_run


@pytest.mark.parametrize(
    "mutate",
    [
        _swap_adjacent_distinct_lines,
        _drop_nonblank_line,
        _duplicate_nonblank_line,
        _change_line_punctuation,
        _join_adjacent_distinct_lines,
    ],
    ids=[
        "swapped-distinct-lines",
        "dropped-line",
        "duplicated-line",
        "changed-punctuation",
        "joined-adjacent-lines",
    ],
)
def test_verify_pdf_rejects_mutated_poppler_layout_text(
    tmp_path, monkeypatch: pytest.MonkeyPatch, mutate
) -> None:
    artifacts = _clean_artifacts()
    runtime = resolve_poppler_runtime()
    calls: list[tuple[str, tuple[str, ...]]] = []
    monkeypatch.setattr(quality, "_run", _layout_mutating_run(calls, mutate))

    with pytest.raises(DocumentQualityError) as excinfo:
        quality._verify_pdf(
            artifacts.cv_pdf, artifacts.editable.cv_text, runtime, tmp_path
        )

    assert str(excinfo.value) == "Poppler ATS text order differs from rendered order"
    assert calls[0][0] == "pdfinfo"
    assert calls[-1][0] == "pdftotext"
    assert "-layout" in calls[-1][1]
    assert not any(tool == "pdftoppm" for tool, _ in calls)
    assert not any("-bbox-layout" in arguments for _, arguments in calls)


def test_missing_poppler_and_duplicate_prose_fail_closed(tmp_path) -> None:
    with pytest.raises(DocumentQualityError, match="required but unavailable"):
        resolve_poppler_runtime(tmp_path)

    artifacts = _clean_artifacts()
    duplicate = (
        artifacts.editable.cv_text
        + "\n- Built an evidence-linked application composition pipeline.\n"
    )
    editable = replace(
        artifacts.editable,
        cv_text=duplicate,
        cv_sha256=hashlib.sha256(duplicate.encode()).hexdigest(),
    )
    with pytest.raises(DocumentQualityError, match="duplicate prose"):
        verify_document_quality(_rehash_editable(artifacts, editable))
    assert _duplicate_prose(duplicate)


def test_geometry_and_structure_negative_controls(tmp_path) -> None:
    artifact = _clean_artifacts().cv_pdf
    with pytest.raises(DocumentQualityError, match="not A4"):
        _parse_pdfinfo(
            "Pages: 1\nEncrypted: no\nForm: none\nJavaScript: no\nPage size: 612 x 792 pts\n",
            artifact,
        )
    bbox = tmp_path / "tight.html"
    bbox.write_text(
        '<html><body><doc><page width="595" height="842">'
        '<word xMin="10" yMin="40" xMax="100" yMax="60">text</word>'
        "</page></doc></body></html>",
        encoding="utf-8",
    )
    with pytest.raises(DocumentQualityError, match="minimum page margin"):
        _minimum_margin(bbox, (595.0, 842.0), 1)
    bbox.write_text(
        '<html><body><doc><page width="595" height="842">'
        '<word xMin="35.5" yMin="40" xMax="100" yMax="60">text</word>'
        "</page></doc></body></html>",
        encoding="utf-8",
    )
    assert _minimum_margin(bbox, (595.0, 842.0), 1) == 36.0
    with pytest.raises(DocumentQualityError, match="font hierarchy"):
        _font_hierarchy(replace(artifact, pdf_bytes=b"%PDF-1.4\n/F1 10 Tf"))


def test_quality_receipt_cannot_claim_release_or_visual_review() -> None:
    receipt = verify_document_quality(_clean_artifacts())
    with pytest.raises(DocumentQualityError, match="release authority"):
        replace(receipt, release_authority=True)
    with pytest.raises(DocumentQualityError, match="visual judgement"):
        replace(receipt, visual_judgement="pass")


def test_visual_review_rasterizer_bounds_pages_and_private_temp_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = quality.PopplerRuntime(
        version="pdftoppm version synthetic",
        tool_paths=tuple((tool, f"/synthetic/{tool}") for tool in quality.POPPLER_TOOLS),
        tool_sha256=tuple((tool, "a" * 64) for tool in quality.POPPLER_TOOLS),
        runtime_sha256="b" * 64,
    )
    png = b"\x89PNG\r\n\x1a\nsynthetic-page"
    observed: dict[str, object] = {}

    def fake_run(_runtime, tool, *arguments):
        if tool == "pdfinfo":
            pdf_path = Path(arguments[0])
            observed["directory_mode"] = os.stat(pdf_path.parent).st_mode & 0o777
            observed["pdf_mode"] = os.stat(pdf_path).st_mode & 0o777
            observed["pdf_bytes"] = pdf_path.read_bytes()
            return SimpleNamespace(stdout="Pages:          1\n")
        prefix = Path(arguments[-1])
        page_path = prefix.with_name("page-1.png")
        page_path.write_bytes(png)
        observed["page_path"] = page_path
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(quality, "_run", fake_run)
    result = quality.rasterize_review_pdf_pages(
        b"%PDF-1.4\nsynthetic-pdf",
        "cv",
        poppler_runtime=runtime,
    )

    assert result == (png,)
    assert observed["directory_mode"] == 0o700
    assert observed["pdf_mode"] == 0o600
    assert observed["pdf_bytes"] == b"%PDF-1.4\nsynthetic-pdf"
    assert not Path(observed["page_path"]).exists()


def test_visual_review_rasterizer_refuses_excess_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = quality.PopplerRuntime(
        version="pdftoppm version synthetic",
        tool_paths=tuple((tool, f"/synthetic/{tool}") for tool in quality.POPPLER_TOOLS),
        tool_sha256=tuple((tool, "a" * 64) for tool in quality.POPPLER_TOOLS),
        runtime_sha256="b" * 64,
    )
    monkeypatch.setattr(
        quality,
        "_run",
        lambda *_args: SimpleNamespace(stdout="Pages:          3\n"),
    )
    with pytest.raises(DocumentQualityError, match="page count is outside policy"):
        quality.rasterize_review_pdf_pages(
            b"%PDF-1.4\nsynthetic-pdf",
            "cv",
            poppler_runtime=runtime,
        )
