"""Exact, fail-closed authority for the certified JAA-04 Graphcore vacancy.

This module does not discover or refresh vacancies.  It verifies one already
certified, externally stored corpus and returns a typed projection only after
every identity on the JAA-04 lineage has been checked.
"""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .corpus_publication import INVENTORY_FORMAT, canonical_bytes, sha256_file
from .employer_research import content_hash


CORPUS_IDENTITY = "f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
CORPUS_DIRECTORY = f"sha256-{CORPUS_IDENTITY}"
INVENTORY_SHA256 = CORPUS_IDENTITY
INVENTORY_FILES_SHA256 = (
    "e3c155f02a76b150334f1efa555f727b20a9bb7520dbb6e69e8ecb53ed95c726"
)

GRAPHCORE_JOB_KEY = "greenhouse:graphcore:8420314002"
GRAPHCORE_COMPANY = "Graphcore"
GRAPHCORE_TITLE = "Software Engineer in Build Engineering"
GRAPHCORE_URL = "https://job-boards.greenhouse.io/graphcore/jobs/8420314002"
GRAPHCORE_SOURCE_ID = "source:greenhouse:graphcore:8420314002:typed-authority"

TRACKED_SEED_SHA256 = (
    "48b00c06b7b0f9b5d10d87fda267c7a3b03725c0ede340478f326e42a7229499"
)
TRACKED_SEED_RECORDS_SHA256 = (
    "00bc655486e5a4e76450bc015e0a9647354aa85215f62ec2363802e9654ef504"
)
TRACKED_SEED_PAYLOAD_SHA256 = (
    "681aa4041e5545da8dc1a5c4e4359766d5881991a7ab216bd8b28501155d99c1"
)
ADMITTED_QUEUE_PAYLOAD_SHA256 = (
    "9c35c1dd0c176745dd1887532b04ce502d1523c870b5ec55516b271d7f38e50e"
)
QUEUE_BODY_CONTENT_SHA256 = (
    "8a46453a2b81bbf123bdb740cc38567a610164315019cc60bb0f39395dbf984e"
)
DOSSIER_SHA256 = (
    "bf8692e5977cf20f18b2fe7ba3a19f29678a21c4b428dd91cf937ac580b8da4a"
)
RAW_RESPONSE_SHA256 = (
    "49097938daa0a352cbbf6e26de54c355dcc0090060e1fd2fde2288a32d26a061"
)
RAW_RESPONSE_RELATIVE_PATH = f"raw/sha256/49/{RAW_RESPONSE_SHA256}"
ROBOTS_RESPONSE_SHA256 = (
    "0bc35a3bc59e53b4932c848ba1f33890320d2de73fa0c1357555dd79c5629be9"
)
ROBOTS_RESPONSE_RELATIVE_PATH = f"raw/sha256/0b/{ROBOTS_RESPONSE_SHA256}"

LINEAGE_FILES: Mapping[str, tuple[str, int]] = {
    "admission/queue_snapshot.json": (
        "395b9a48106b7734abdf63862874bb9ca207149c8a31a9e1d255a0b02408940c",
        2_416_409,
    ),
    "research_manifest.json": (
        "188900fd7a379716790966ca0de354903bba81619b483ce673a0deb22665aea9",
        1_684_831,
    ),
    "frozen_dossiers.json": (
        "0c882cf1f47ef2be649934120a169106530068e7a3a14e91277b0bf05c9b4c02",
        248_449,
    ),
    RAW_RESPONSE_RELATIVE_PATH: (RAW_RESPONSE_SHA256, 27_826),
    ROBOTS_RESPONSE_RELATIVE_PATH: (ROBOTS_RESPONSE_SHA256, 131),
}

REQUIREMENT_ANCHORS: tuple[tuple[str, int], ...] = (
    ("Knowledge of Python/C++ (or similar language)", 14_063),
    ("Experience working in Linux environments", 16_309),
    ("Good communication", 17_398),
)


class CorpusAuthorityError(ValueError):
    """The exact certified JAA-04 authority is absent or inconsistent."""


@dataclass(frozen=True)
class RawRequirementAnchor:
    text: str
    byte_start: int
    byte_length: int
    source_content_sha256: str = RAW_RESPONSE_SHA256


@dataclass(frozen=True)
class FrozenVacancyAuthority:
    corpus_root: Path
    corpus_identity: str
    inventory_sha256: str
    inventory_files_sha256: str
    job_key: str
    company: str
    title: str
    vacancy_url: str
    observed_at: str
    opportunity_score_bp: int
    tracked_seed_payload_sha256: str
    admitted_queue_payload_sha256: str
    queue_body_content_sha256: str
    dossier_sha256: str
    raw_response_sha256: str
    raw_response_path: Path
    raw_response_bytes: bytes
    robots_response_path: Path
    robots_response_bytes: bytes
    queue_payload: Mapping[str, Any]
    dossier: Mapping[str, Any]
    requirement_anchors: tuple[RawRequirementAnchor, ...]


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except FileNotFoundError as exc:
        raise CorpusAuthorityError(f"certified corpus unavailable: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusAuthorityError(f"certified corpus document is unreadable: {path}") from exc
    if not isinstance(value, dict):
        raise CorpusAuthorityError(f"certified corpus document is not an object: {path}")
    return value


def _unique_record(
    rows: object,
    *,
    job_key: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(rows, list):
        raise CorpusAuthorityError(f"{label} records are missing")
    matches = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("job_key") == job_key
    ]
    if len(matches) != 1:
        raise CorpusAuthorityError(
            f"{label} must contain exactly one {job_key} record"
        )
    return matches[0]


def _verify_inventory(root: Path) -> dict[str, Mapping[str, Any]]:
    inventory_path = root / "corpus_inventory.json"
    if sha256_file(inventory_path) != INVENTORY_SHA256:
        raise CorpusAuthorityError("certified corpus inventory identity mismatch")
    inventory = _load_object(inventory_path)
    if inventory.get("schema_version") != INVENTORY_FORMAT:
        raise CorpusAuthorityError("certified corpus inventory schema mismatch")
    rows = inventory.get("files")
    if not isinstance(rows, list):
        raise CorpusAuthorityError("certified corpus inventory file list is missing")
    paths = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(paths) != len(rows) or len(paths) != len(set(paths)):
        raise CorpusAuthorityError("certified corpus inventory paths are invalid")
    calculated_files_hash = hashlib.sha256(canonical_bytes(rows)).hexdigest()
    if (
        inventory.get("files_hash") != INVENTORY_FILES_SHA256
        or calculated_files_hash != INVENTORY_FILES_SHA256
    ):
        raise CorpusAuthorityError("certified corpus inventory files hash mismatch")
    return {str(row["path"]): row for row in rows}


def _verify_lineage_files(
    root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
) -> None:
    for relative, (expected_sha256, expected_size) in LINEAGE_FILES.items():
        row = inventory.get(relative)
        if (
            row is None
            or row.get("sha256") != expected_sha256
            or row.get("size_bytes") != expected_size
        ):
            raise CorpusAuthorityError(
                f"certified corpus inventory binding mismatch: {relative}"
            )
        path = root / relative
        try:
            actual_size = path.stat().st_size
            actual_sha256 = sha256_file(path)
        except FileNotFoundError as exc:
            raise CorpusAuthorityError(
                f"certified corpus lineage file unavailable: {relative}"
            ) from exc
        if actual_size != expected_size or actual_sha256 != expected_sha256:
            raise CorpusAuthorityError(
                f"certified corpus lineage bytes mismatch: {relative}"
            )
    for relative in (RAW_RESPONSE_RELATIVE_PATH, ROBOTS_RESPONSE_RELATIVE_PATH):
        raw_mode = stat.S_IMODE((root / relative).stat().st_mode)
        if raw_mode != 0o444:
            raise CorpusAuthorityError("certified raw response mode must be 0444")


def _verify_seed(seed_path: Path) -> dict[str, Any]:
    try:
        seed_sha256 = sha256_file(seed_path)
    except FileNotFoundError as exc:
        raise CorpusAuthorityError(f"tracked JAA-04 seed unavailable: {seed_path}") from exc
    if seed_sha256 != TRACKED_SEED_SHA256:
        raise CorpusAuthorityError("tracked JAA-04 seed file identity mismatch")
    seed = _load_object(seed_path)
    if (
        seed.get("records_hash") != TRACKED_SEED_RECORDS_SHA256
        or content_hash(seed.get("records")) != TRACKED_SEED_RECORDS_SHA256
    ):
        raise CorpusAuthorityError("tracked JAA-04 seed records identity mismatch")
    row = _unique_record(
        seed.get("records"),
        job_key=GRAPHCORE_JOB_KEY,
        label="tracked seed",
    )
    if (
        row.get("board") != "greenhouse"
        or row.get("company") != GRAPHCORE_COMPANY
        or str(row.get("title") or "").strip() != GRAPHCORE_TITLE
        or row.get("url") != GRAPHCORE_URL
        or row.get("payload_hash") != TRACKED_SEED_PAYLOAD_SHA256
    ):
        raise CorpusAuthorityError("tracked JAA-04 Graphcore seed binding mismatch")
    return row


def _validate_hash_domains(
    queue_record: Mapping[str, Any],
    manifest_record: Mapping[str, Any],
    seed_record: Mapping[str, Any],
) -> None:
    """Keep the seed, admitted payload, and body-content identities distinct."""
    if seed_record.get("payload_hash") != TRACKED_SEED_PAYLOAD_SHA256:
        raise CorpusAuthorityError("tracked seed payload hash mismatch")
    if queue_record.get("payload_hash") != ADMITTED_QUEUE_PAYLOAD_SHA256:
        raise CorpusAuthorityError("admitted queue payload hash mismatch")
    if queue_record.get("content_sha256") != QUEUE_BODY_CONTENT_SHA256:
        raise CorpusAuthorityError("queue body content hash mismatch")
    if manifest_record.get("admitted_payload_hash") != ADMITTED_QUEUE_PAYLOAD_SHA256:
        raise CorpusAuthorityError("manifest admitted payload hash mismatch")
    if len({
        TRACKED_SEED_PAYLOAD_SHA256,
        ADMITTED_QUEUE_PAYLOAD_SHA256,
        QUEUE_BODY_CONTENT_SHA256,
    }) != 3:
        raise CorpusAuthorityError("JAA-04 hash domains are not distinct")


def _validate_vacancy_identity(
    queue_record: Mapping[str, Any],
    manifest_record: Mapping[str, Any],
) -> None:
    decision = queue_record.get("opportunity0_decision")
    if (
        queue_record.get("company") != GRAPHCORE_COMPANY
        or str(queue_record.get("title") or "").strip() != GRAPHCORE_TITLE
        or queue_record.get("url") != GRAPHCORE_URL
        or not isinstance(decision, dict)
        or decision.get("decision") != "pass"
        or decision.get("score_bp") != 8425
        or manifest_record.get("company") != GRAPHCORE_COMPANY
        or str(manifest_record.get("role") or "").strip() != GRAPHCORE_TITLE
        or manifest_record.get("vacancy_url") != GRAPHCORE_URL
    ):
        raise CorpusAuthorityError("Graphcore vacancy identity or admission mismatch")


def _verify_graphcore_documents(
    root: Path,
    seed_record: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    queue = _load_object(root / "admission/queue_snapshot.json")
    manifest = _load_object(root / "research_manifest.json")
    dossiers = _load_object(root / "frozen_dossiers.json")
    queue_record = _unique_record(
        queue.get("records"),
        job_key=GRAPHCORE_JOB_KEY,
        label="admission snapshot",
    )
    manifest_record = _unique_record(
        manifest.get("records"),
        job_key=GRAPHCORE_JOB_KEY,
        label="research manifest",
    )
    dossier = _unique_record(
        dossiers.get("dossiers"),
        job_key=GRAPHCORE_JOB_KEY,
        label="frozen dossiers",
    )
    _validate_hash_domains(queue_record, manifest_record, seed_record)
    payload = queue_record.get("payload")
    if not isinstance(payload, dict):
        raise CorpusAuthorityError("admitted queue payload is missing")
    body = payload.get("body")
    if not isinstance(body, str) or (
        hashlib.sha256(body.encode("utf-8")).hexdigest()
        != QUEUE_BODY_CONTENT_SHA256
    ):
        raise CorpusAuthorityError("admitted queue body bytes mismatch")
    _validate_vacancy_identity(queue_record, manifest_record)
    if (
        manifest_record.get("dossier_hash") != DOSSIER_SHA256
        or content_hash(dossier) != DOSSIER_SHA256
        or manifest_record.get("content_sha256") != RAW_RESPONSE_SHA256
    ):
        raise CorpusAuthorityError("Graphcore dossier lineage mismatch")
    sources = dossier.get("sources")
    source = (
        sources[0]
        if isinstance(sources, list) and len(sources) == 1
        and isinstance(sources[0], dict)
        else None
    )
    if (
        source is None
        or source.get("id") != GRAPHCORE_SOURCE_ID
        or source.get("content_sha256") != RAW_RESPONSE_SHA256
        or source.get("raw_response_ref") != f"sha256/49/{RAW_RESPONSE_SHA256}"
    ):
        raise CorpusAuthorityError("Graphcore typed source lineage mismatch")
    raw_bytes = (root / RAW_RESPONSE_RELATIVE_PATH).read_bytes()
    return queue_record, dossier, raw_bytes


def _verify_requirement_anchors(raw_bytes: bytes) -> tuple[RawRequirementAnchor, ...]:
    anchors: list[RawRequirementAnchor] = []
    for text, expected_start in REQUIREMENT_ANCHORS:
        encoded = text.encode("utf-8")
        positions: list[int] = []
        start = 0
        while True:
            found = raw_bytes.find(encoded, start)
            if found < 0:
                break
            positions.append(found)
            start = found + 1
        if positions != [expected_start]:
            raise CorpusAuthorityError(
                f"raw requirement anchor is absent, duplicated, or moved: {text}"
            )
        anchors.append(
            RawRequirementAnchor(
                text=text,
                byte_start=expected_start,
                byte_length=len(encoded),
            )
        )
    return tuple(anchors)


def verify_graphcore_corpus(
    corpus_root: str | Path,
    tracked_seed_path: str | Path,
) -> FrozenVacancyAuthority:
    """Verify and project the exact certified Graphcore JAA-04 authority."""
    root = Path(corpus_root)
    if not root.is_dir():
        raise CorpusAuthorityError(f"certified corpus unavailable: {root}")
    if root.name != CORPUS_DIRECTORY:
        raise CorpusAuthorityError("certified corpus directory identity mismatch")
    inventory = _verify_inventory(root)
    _verify_lineage_files(root, inventory)
    seed_record = _verify_seed(Path(tracked_seed_path))
    queue_record, dossier, raw_bytes = _verify_graphcore_documents(root, seed_record)
    anchors = _verify_requirement_anchors(raw_bytes)
    decision = queue_record["opportunity0_decision"]
    return FrozenVacancyAuthority(
        corpus_root=root.resolve(),
        corpus_identity=CORPUS_IDENTITY,
        inventory_sha256=INVENTORY_SHA256,
        inventory_files_sha256=INVENTORY_FILES_SHA256,
        job_key=GRAPHCORE_JOB_KEY,
        company=GRAPHCORE_COMPANY,
        title=GRAPHCORE_TITLE,
        vacancy_url=GRAPHCORE_URL,
        observed_at=str(queue_record["observed_at"]),
        opportunity_score_bp=int(decision["score_bp"]),
        tracked_seed_payload_sha256=TRACKED_SEED_PAYLOAD_SHA256,
        admitted_queue_payload_sha256=ADMITTED_QUEUE_PAYLOAD_SHA256,
        queue_body_content_sha256=QUEUE_BODY_CONTENT_SHA256,
        dossier_sha256=DOSSIER_SHA256,
        raw_response_sha256=RAW_RESPONSE_SHA256,
        raw_response_path=(root / RAW_RESPONSE_RELATIVE_PATH).resolve(),
        raw_response_bytes=raw_bytes,
        robots_response_path=(root / ROBOTS_RESPONSE_RELATIVE_PATH).resolve(),
        robots_response_bytes=(root / ROBOTS_RESPONSE_RELATIVE_PATH).read_bytes(),
        queue_payload=dict(queue_record["payload"]),
        dossier=dossier,
        requirement_anchors=anchors,
    )
