"""Immutable non-certifying evidence receipt for the JAA-09 Phase-A run."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .corpus_publication import canonical_bytes
from .jaa04_corpus_authority import (
    ADMITTED_QUEUE_PAYLOAD_SHA256,
    CORPUS_IDENTITY,
    DOSSIER_SHA256,
    GRAPHCORE_COMPANY,
    GRAPHCORE_JOB_KEY,
    GRAPHCORE_TITLE,
    GRAPHCORE_URL,
    INVENTORY_FILES_SHA256,
    QUEUE_BODY_CONTENT_SHA256,
    RAW_RESPONSE_SHA256,
    TRACKED_SEED_PAYLOAD_SHA256,
)


RECEIPT_SCHEMA = "jaa09.real-vacancy-local-receipt.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_PII_KEYS = frozenset(
    {
        "full_name",
        "email",
        "phone",
        "city",
        "cover_note",
        "cv_text",
        "cover_letter_text",
    }
)


class RealVacancyReceiptError(ValueError):
    """The run evidence cannot satisfy the non-certifying receipt contract."""


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RealVacancyReceiptError(f"{label} must be an object")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RealVacancyReceiptError(f"{label} must be a full lowercase SHA-256")
    return value


def _reject_pii_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _PII_KEYS:
                raise RealVacancyReceiptError("receipt contains a prohibited PII field")
            _reject_pii_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_pii_keys(child)


def validate_real_vacancy_receipt(document: Mapping[str, Any]) -> None:
    if (
        document.get("schema_version") != RECEIPT_SCHEMA
        or document.get("certifies_slice") is not False
    ):
        raise RealVacancyReceiptError(
            "real-vacancy run receipt must be non-certifying schema v1"
        )
    try:
        created_at = datetime.fromisoformat(str(document["created_at"]))
    except (KeyError, ValueError) as exc:
        raise RealVacancyReceiptError("receipt created_at is invalid") from exc
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise RealVacancyReceiptError("receipt created_at must be timezone-aware")
    _reject_pii_keys(document)

    corpus = _mapping(document.get("corpus_binding"), "corpus binding")
    expected_corpus = {
        "corpus_inventory_sha256": CORPUS_IDENTITY,
        "files_hash": INVENTORY_FILES_SHA256,
        "official_response_sha256": RAW_RESPONSE_SHA256,
        "official_response_size": 27_826,
        "official_response_mode": "0444",
        "dossier_sha256": DOSSIER_SHA256,
        "queue_content_sha256": QUEUE_BODY_CONTENT_SHA256,
        "queue_payload_hash": ADMITTED_QUEUE_PAYLOAD_SHA256,
        "tracked_seed_payload_hash": TRACKED_SEED_PAYLOAD_SHA256,
    }
    if not isinstance(corpus.get("corpus_root"), str) or not corpus["corpus_root"]:
        raise RealVacancyReceiptError("receipt corpus root is missing")
    if any(corpus.get(key) != value for key, value in expected_corpus.items()):
        raise RealVacancyReceiptError("receipt corpus binding differs from authority")
    domains = _mapping(corpus.get("hash_domains"), "corpus hash domains")
    if domains != {
        "queue_content_sha256": "normalized-vacancy-body-utf8",
        "queue_payload_hash": "admitted-queue-record",
        "tracked_seed_payload_hash": "repo-tracked-seed-record",
    }:
        raise RealVacancyReceiptError("receipt hash-domain labels are incomplete")

    vacancy = _mapping(document.get("vacancy_identity"), "vacancy identity")
    if any(
        vacancy.get(key) != value
        for key, value in {
            "job_key": GRAPHCORE_JOB_KEY,
            "company": GRAPHCORE_COMPANY,
            "title": GRAPHCORE_TITLE,
            "url": GRAPHCORE_URL,
            "opportunity0_score_bp": 8425,
            "opportunity1_reassessment": "no_changes",
        }.items()
    ) or not isinstance(vacancy.get("observed_at"), str):
        raise RealVacancyReceiptError("receipt vacancy identity differs from authority")

    candidate = _mapping(document.get("candidate_boundary"), "candidate boundary")
    if candidate.get("candidate_projection") != "fixture":
        raise RealVacancyReceiptError("Phase-A receipt requires the fixture candidate")
    _digest(candidate.get("projection_content_sha256"), "candidate projection hash")
    if candidate.get("disclosure") != (
        "deterministic approved fixture candidate projection; not a real person"
    ):
        raise RealVacancyReceiptError("fixture candidate disclosure is incomplete")

    release = _mapping(document.get("release_binding"), "release binding")
    for key in (
        "release_manifest_sha256",
        "release_token_sha256",
        "application_source_sha256",
        "vacancy_sha256",
        "artifact_set_sha256",
        "artifact_receipt_sha256",
    ):
        _digest(release.get(key), key.replace("_", " "))

    browser = _mapping(document.get("browser_evidence"), "browser evidence")
    for key in (
        "workflow_sha256",
        "receipt_id",
        "receipt_payload_sha256",
        "screenshot_sha256",
        "field_map_sha256",
        "submit_event_sha256",
    ):
        _digest(browser.get(key), key.replace("_", " "))
    if (
        not isinstance(browser.get("run_id"), str)
        or not browser["run_id"]
        or browser.get("submit_count") != 1
        or browser.get("non_loopback_requests") != 0
    ):
        raise RealVacancyReceiptError("browser evidence boundary is incomplete")

    source = _mapping(document.get("source_environment"), "source environment")
    if (
        not isinstance(source.get("source_git_revision"), str)
        or not _SHA1.fullmatch(source["source_git_revision"])
        or not isinstance(source.get("source_tree"), str)
        or not _SHA1.fullmatch(source["source_tree"])
        or not isinstance(source.get("source_content_revision"), str)
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            source["source_content_revision"],
        )
        or not str(source.get("interpreter_path") or "").endswith(
            "/.venv/bin/python"
        )
        or source.get("implementation") != "CPython"
        or source.get("python_version") != "3.12.13"
        or source.get("playwright_version") != "1.61.0"
        or not isinstance(source.get("chromium_version"), str)
        or not source["chromium_version"]
        or not isinstance(source.get("platform"), str)
        or not source["platform"]
    ):
        raise RealVacancyReceiptError("source or locked-environment binding is invalid")

    disclosures = _mapping(document.get("disclosures"), "disclosures")
    if disclosures != {
        "candidate_projection_scope": "fixture_only",
        "receipt_authenticity_scope": "in_process_fixture_receipt_forgery_residual",
        "ats_scope": "local_simulated_ats_only",
        "filesystem_trust_limit": "operator_control_root_local_filesystem",
        "real_application_submitted": False,
        "external_authority_granted": False,
    }:
        raise RealVacancyReceiptError("receipt disclosures are incomplete")


def write_real_vacancy_receipt(
    document: Mapping[str, Any],
    control_root: str | Path,
) -> Path:
    """Validate, atomically write, fsync and freeze one content-addressed receipt."""
    validate_real_vacancy_receipt(document)
    body = canonical_bytes(document)
    digest = hashlib.sha256(body).hexdigest()
    root = Path(control_root).resolve(strict=True)
    if not root.is_dir():
        raise RealVacancyReceiptError("control root is not a directory")
    target = root / f"jaa09-real-vacancy-local-receipt-sha256-{digest}.json"
    if target.exists():
        if (
            target.read_bytes() != body
            or stat.S_IMODE(target.stat().st_mode) != 0o444
        ):
            raise RealVacancyReceiptError("existing receipt identity collision")
        return target
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return target
