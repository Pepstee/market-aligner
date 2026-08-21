from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cv_generation import document_quality as quality
from career_automation.rendering import (
    ApplicationArtifacts,
    EditableArtifacts,
    _artifact,
)
from cv_generation.document_quality import (
    DocumentQualityError,
    _duplicate_prose,
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
        hashlib.sha256(answers.encode()).hexdigest(),
    )
    cv = _artifact(
        "cv",
        ((
            "Alex Example",
            "alex@example.test | +44 7700 900123 | London",
            "Professional Summary",
            "- Delivered reliable services with independently verified evidence.",
            "Core Capabilities",
            "- Designed deterministic workflow automation around bounded authority.",
            "Projects",
            "- Built an evidence-linked application composition pipeline.",
        ),),
    )
    letter = _artifact(
        "cover_letter",
        ((
            "Alex Example",
            "alex@example.test",
            "+44 7700 900123",
            "London",
            "Software Engineer",
            "Example Ltd",
            "I am applying because the role matches my tested automation work.",
            "My project evidence demonstrates reliable delivery and careful validation.",
            "Example Ltd's documented service focus makes the work particularly relevant.",
            "I would welcome the opportunity to discuss the engineering challenges.",
        ),),
    )
    source_id = "a" * 64
    artifact_set = hashlib.sha256(
        "\n".join(
            (
                source_id,
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


def _rehash_editable(artifacts: ApplicationArtifacts, editable: EditableArtifacts) -> ApplicationArtifacts:
    artifact_set = hashlib.sha256(
        "\n".join(
            (
                artifacts.source_id,
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


def test_missing_poppler_and_duplicate_prose_fail_closed(tmp_path) -> None:
    with pytest.raises(DocumentQualityError, match="required but unavailable"):
        resolve_poppler_runtime(tmp_path)

    artifacts = _clean_artifacts()
    duplicate = artifacts.editable.cv_text + "\n- Built an evidence-linked application composition pipeline.\n"
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
    with pytest.raises(DocumentQualityError, match="font hierarchy"):
        _font_hierarchy(replace(artifact, pdf_bytes=b"%PDF-1.4\n/F1 10 Tf"))


def test_quality_receipt_cannot_claim_release_or_visual_review() -> None:
    receipt = verify_document_quality(_clean_artifacts())
    with pytest.raises(DocumentQualityError, match="release authority"):
        replace(receipt, release_authority=True)
    with pytest.raises(DocumentQualityError, match="visual judgement"):
        replace(receipt, visual_judgement="pass")
