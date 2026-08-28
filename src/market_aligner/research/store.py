"""Profile-aware assessment state and deterministic employer-research queue."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from market_aligner.assessment.scoring import FitStatus, ScoreResult
from market_aligner.config import owner_private_umask
from market_aligner.profiler.schema import validate_profile_id
from market_aligner.state.vacancies import (
    JobDatabase,
    ProjectionConflict,
)

from .models import (
    RESEARCH_ARCHIVE_ROOT_POLICY_SHA256,
    ResearchDossier,
    ResearchEvidenceBinding,
    ResearchTask,
    research_refresh_bridge_sha256,
    research_refresh_preserves_source_authority,
)


_BYTE_SELECTOR = re.compile(r"^bytes:(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")
_PROCESSING_SCORE_ACCEPTED = "processing_score_accepted"
_ELIGIBILITY_DECIDED = "eligibility_decided"
_EVENT_TYPES = frozenset({_PROCESSING_SCORE_ACCEPTED, _ELIGIBILITY_DECIDED})
_RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
_MAX_IDEMPOTENCY_KEY_BYTES = 512
_SCORE_PROJECTION_COLUMNS = (
    "profile_id",
    "job_key",
    "url",
    "title",
    "company",
    "opportunity",
    "fit",
    "final_score",
    "fit_status",
    "extraction_confidence",
    "score_payload_json",
    "score_payload_hash",
    "state",
    "created_at",
    "updated_at",
)
_SCORE_ADVANCED_COLUMNS = (
    "opportunity_decision",
    "opportunity_reason",
    "policy_hash",
)
_SCORE_ROW_COLUMNS = _SCORE_PROJECTION_COLUMNS + _SCORE_ADVANCED_COLUMNS
_EVENT_PROJECTION_COLUMNS = (
    "id",
    "profile_id",
    "job_key",
    "event_type",
    "actor_kind",
    "payload_json",
    "idempotency_key",
    "created_at",
)


def _vacancy_snapshot_sha256(values: dict[str, Any]) -> str | None:
    if (
        values.get("source_content_sha256") is None
        or values.get("promotion_receipt_sha256") is None
    ):
        return None
    return hashlib.sha256(
        json.dumps(
            {
                "company": values["company"],
                "job_key": values["job_key"],
                "promotion_receipt_sha256": values["promotion_receipt_sha256"],
                "schema_version": "market-aligner.research-vacancy-snapshot.v1",
                "source_content_sha256": values["source_content_sha256"],
                "title": values["title"],
                "url": values["url"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS assessments (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  url TEXT NOT NULL,
  title TEXT NOT NULL,
  company TEXT NOT NULL,
  opportunity REAL NOT NULL CHECK(opportunity >= 0 AND opportunity <= 1),
  fit REAL NOT NULL CHECK(fit >= 0 AND fit <= 1),
  final_score REAL NOT NULL CHECK(final_score >= 0 AND final_score <= 100),
  fit_status TEXT NOT NULL CHECK(fit_status IN ('uncalibrated')),
  extraction_confidence REAL,
  score_payload_json TEXT NOT NULL,
  score_payload_hash TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'scored',
  opportunity_decision TEXT CHECK(opportunity_decision IN ('pass','reject')),
  opportunity_reason TEXT,
  policy_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key)
);
CREATE INDEX IF NOT EXISTS assessments_rank
  ON assessments(profile_id,opportunity DESC,final_score DESC);

CREATE TABLE IF NOT EXISTS assessment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK(actor_kind IN ('deterministic','probabilistic','external')),
  payload_json TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS immutable_collection_refresh_event_update
BEFORE UPDATE ON assessment_events
WHEN OLD.event_type='employer_research_collection_refresh_queued'
  OR NEW.event_type='employer_research_collection_refresh_queued'
BEGIN
  SELECT RAISE(ABORT, 'collection refresh assessment events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS immutable_collection_refresh_event_delete
BEFORE DELETE ON assessment_events
WHEN OLD.event_type='employer_research_collection_refresh_queued'
BEGIN
  SELECT RAISE(ABORT, 'collection refresh assessment events are immutable');
END;

CREATE TABLE IF NOT EXISTS employer_research_queue (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','completed','failed')),
  priority INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  lease_owner TEXT,
  lease_until TEXT,
  last_error TEXT,
  refresh_event_id INTEGER,
  refresh_bridge_sha256 TEXT,
  queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE,
  FOREIGN KEY(refresh_event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS employer_dossiers (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  dossier_json TEXT NOT NULL,
  dossier_hash TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS employer_research_evidence (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  dossier_hash TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  vacancy_snapshot_sha256 TEXT NOT NULL,
  promotion_receipt_sha256 TEXT NOT NULL,
  canonical_vacancy_object_sha256 TEXT NOT NULL,
  semantic_receipt_sha256 TEXT NOT NULL,
  receipt_file_sha256 TEXT NOT NULL,
  archive_root_identity TEXT NOT NULL,
  archive_root_policy_sha256 TEXT NOT NULL,
  receipt_relative_path TEXT NOT NULL,
  schema_version TEXT NOT NULL CHECK(schema_version='market-aligner.research-store-binding.v2'),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES employer_dossiers(profile_id,job_key)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessment_promotions (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  track TEXT NOT NULL,
  authority_sha256 TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  processing_config_sha256 TEXT NOT NULL,
  processing_receipt_sha256 TEXT NOT NULL,
  processing_result_sha256 TEXT NOT NULL,
  score_payload_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  receipt_bytes BLOB NOT NULL,
  receipt_sha256 TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS research_requires_opportunity_pass
BEFORE INSERT ON employer_research_queue
WHEN COALESCE((SELECT opportunity_decision FROM assessments
               WHERE profile_id=NEW.profile_id AND job_key=NEW.job_key),'') != 'pass'
BEGIN
  SELECT RAISE(ABORT, 'employer research requires a passed opportunity gate');
END;
"""

_REFRESH_QUEUE_IMMUTABILITY_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS immutable_leased_refresh_bridge
BEFORE UPDATE ON employer_research_queue
WHEN OLD.status='leased' AND OLD.refresh_event_id IS NOT NULL
 AND (NEW.refresh_event_id IS NOT OLD.refresh_event_id
      OR NEW.refresh_bridge_sha256 IS NOT OLD.refresh_bridge_sha256)
BEGIN
  SELECT RAISE(ABORT, 'leased research refresh bridge is immutable');
END;
"""


def canonical_score_payload(result: ScoreResult) -> tuple[str, str]:
    """Exact historical score-payload STRING plus its UTF-8 SHA-256.

    ``json.dumps(asdict(result), ensure_ascii=False, sort_keys=True,
    default=str)`` is the one canonical score payload text; the SHA-256
    is taken over its exact UTF-8 bytes.
    """

    payload = json.dumps(
        asdict(result), ensure_ascii=False, sort_keys=True, default=str
    )
    return payload, hashlib.sha256(payload.encode("utf-8")).hexdigest()

def require_rfc3339_timestamp(value: Any, label: str) -> str:
    """Strict RFC3339: uppercase Z or numeric offset, never 'z'/space."""

    if not isinstance(value, str):
        raise ProjectionConflict(f"{label} must be an RFC3339 string")
    if not 20 <= len(value) <= 64:
        raise ProjectionConflict(
            f"{label} must be 20..64 characters, got {len(value)}"
        )
    if not _RFC3339_PATTERN.fullmatch(value):
        raise ProjectionConflict(
            f"{label} must match RFC3339 with T separator, Z or ±HH:MM: "
            f"{value!r}"
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ProjectionConflict(
            f"{label} must parse as RFC3339: {value!r}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProjectionConflict(f"{label} must be timezone-aware")
    return value

def require_exact_profile_id(value: Any) -> str:
    """The supplied profile_id must be a str equal to its canonical form."""

    if not isinstance(value, str):
        raise ProjectionConflict("profile_id must be a string")
    try:
        canonical = validate_profile_id(value)
    except (ValueError, TypeError) as exc:
        raise ProjectionConflict(
            f"profile_id is malformed: {exc}"
        ) from exc
    if value != canonical:
        raise ProjectionConflict(
            "profile_id must exactly equal its canonical form without "
            "surrounding whitespace"
        )
    return value

def require_bounded_number(
    value: Any, label: str, low: float, high: float
) -> float:
    """Exact numeric primitive: finite int/float (never bool), in range.

    Returns the canonical float used for REAL projection comparison;
    absurd integers that overflow float() refuse as conflicts.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProjectionConflict(
            f"{label} must be an int or float without bool"
        )
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ProjectionConflict(
            f"{label} is not a finite representable number"
        ) from exc
    if not math.isfinite(number):
        raise ProjectionConflict(f"{label} must be finite")
    if not low <= number <= high:
        raise ProjectionConflict(f"{label} must be in [{low}, {high}]")
    return number

def _require_text(value: Any, label: str, low: int, high: int) -> str:
    if not isinstance(value, str):
        raise ProjectionConflict(f"{label} must be a string")
    if not low <= len(value) <= high:
        raise ProjectionConflict(
            f"{label} must hold {low}..{high} characters"
        )
    return value

@dataclass(frozen=True)
class ScoreInsertPlan:
    profile_id: str
    job_key: str
    url: str
    title: str
    company: str
    opportunity: float
    fit: float
    final_score: float
    extraction_confidence: float | None
    score_payload_json: str
    score_payload_hash: str
    created_at: str  # created_at == updated_at == accepted_at

@dataclass(frozen=True)
class ScoreReusePlan:
    profile_id: str
    job_key: str
    score_payload_hash: str
    created_at: str
    updated_at: str

@dataclass(frozen=True)
class ScoreReadPlan:
    action: str  # exactly "insert" or "reuse"
    insert: ScoreInsertPlan | None
    reuse: ScoreReusePlan | None

@dataclass(frozen=True)
class AcceptedScoreProjection:
    """Exact durable assessment row after reread (insert or reuse)."""

    profile_id: str
    job_key: str
    url: str
    title: str
    company: str
    opportunity: float
    fit: float
    final_score: float
    fit_status: str
    extraction_confidence: float | None
    score_payload_json: str
    score_payload_hash: str
    state: str
    created_at: str
    updated_at: str

@dataclass(frozen=True)
class AcceptedScoreOutcome:
    action: str  # exactly "insert" or "reuse"
    plan: ScoreReadPlan
    projection: AcceptedScoreProjection | None

def canonical_accepted_score_fields(
    *,
    result: ScoreResult,
    url: str,
    title: str,
    company: str,
    extraction_confidence: float | None,
) -> tuple[str, str, str, float, float, float, float | None, str, str]:
    """Validate identity/primitives and freeze the exact field tuple."""

    require_exact_profile_id(result.profile_id)
    if result.fit_status is not FitStatus.UNCALIBRATED:
        raise ProjectionConflict(
            "fit_status must be exactly the uncalibrated owner enum value"
        )
    _require_text(result.job_key, "job_key", 3, 256)
    _require_text(url, "url", 1, 4096)
    _require_text(title, "title", 1, 4096)
    _require_text(company, "company", 0, 4096)
    opportunity = require_bounded_number(result.opportunity, "opportunity", 0, 1)
    fit = require_bounded_number(result.fit, "fit", 0, 1)
    final_score = require_bounded_number(result.final, "final_score", 0, 100)
    confidence = (
        None
        if extraction_confidence is None
        else require_bounded_number(
            extraction_confidence, "extraction_confidence", 0, 1
        )
    )
    payload, digest = canonical_score_payload(result)
    return url, title, company, opportunity, fit, final_score, confidence, payload, digest

def _row_to_columns(
    row: Any, columns: tuple[str, ...]
) -> dict[str, Any]:
    """Canonical stored-row -> column-name mapping for C1 reads.

    Accepts sqlite3.Row / any Mapping (key set must equal the requested
    columns exactly) or a non-string Sequence of exact length. Never
    mutates the row or any connection row_factory.
    """

    label = ", ".join(columns)
    if isinstance(row, (str, bytes, bytearray)):
        raise ProjectionConflict(
            f"malformed stored row ({label}): string or bytes value"
        )
    if hasattr(row, "keys") and callable(row.keys):
        try:
            keys = list(row.keys())
        except Exception as exc:
            raise ProjectionConflict(
                f"malformed stored row ({label}): keys() failed: {exc}"
            ) from exc
        if not all(isinstance(key, str) for key in keys):
            raise ProjectionConflict(
                f"malformed stored row ({label}): keys must be strings"
            )
        if sorted(keys) != sorted(columns):
            raise ProjectionConflict(
                f"malformed stored row ({label}): column shape mismatch"
            )
        values: dict[str, Any] = {}
        for column in columns:
            try:
                values[column] = row[column]
            except Exception as exc:
                raise ProjectionConflict(
                    f"malformed stored row ({label}): {column} inaccessible"
                ) from exc
        return values
    if isinstance(row, Sequence):
        if len(row) != len(columns):
            raise ProjectionConflict(
                f"malformed stored row ({label}): expected exactly "
                f"{len(columns)} values, got {len(row)}"
            )
        return dict(zip(columns, row))
    raise ProjectionConflict(
        f"malformed stored row ({label}): unsupported type "
        f"{type(row).__name__}"
    )

def _score_row_problems(row, *, expected_profile_id: str,
                        expected_job_key: str, expected_url: str, expected_title: str,
                        expected_company: str, expected_opportunity: float,
                        expected_fit: float, expected_final: float,
                        expected_status: str, expected_confidence,
                        expected_payload: str, expected_digest: str) -> list[str]:
    """Pure comparator over an explicit-column row mapping/tuple."""

    problems: list[str] = []
    try:
        stored = _row_to_columns(row, _SCORE_ROW_COLUMNS)
    except ProjectionConflict as exc:
        return [str(exc)]
    stored_ranges = {
        "opportunity": (expected_opportunity, 0, 1),
        "fit": (expected_fit, 0, 1),
        "final_score": (expected_final, 0, 100),
    }
    for label, (expected_value, low, high) in stored_ranges.items():
        try:
            stored_number = require_bounded_number(
                stored.get(label), f"stored {label}", low, high
            )
        except ProjectionConflict as exc:
            problems.append(str(exc))
            continue
        if stored_number != expected_value:
            problems.append(f"stored {label} differs from the accepted score")
    stored_confidence = stored.get("extraction_confidence")
    if stored_confidence is not None:
        try:
            require_bounded_number(
                stored_confidence, "stored extraction_confidence", 0, 1
            )
        except ProjectionConflict as exc:
            problems.append(str(exc))
    if stored_confidence != expected_confidence:
        problems.append("stored extraction_confidence differs from the accepted score")
    for column, wanted in (
        ("profile_id", expected_profile_id),
        ("job_key", expected_job_key),
    ):
        value = stored.get(column)
        if not isinstance(value, str) or value != wanted:
            problems.append(f"stored {column} differs from the accepted score")
    pairs = (
        ("url", expected_url), ("title", expected_title),
        ("company", expected_company),
        ("fit_status", expected_status),
        ("score_payload_json", expected_payload),
        ("score_payload_hash", expected_digest),
    )
    for column, expected in pairs:
        value = stored.get(column)
        if not isinstance(value, str) or value != expected:
            problems.append(f"stored {column} differs from the accepted score")
    if stored.get("state") != "scored":
        problems.append("advanced state is not 'scored'")
    for advanced in ("opportunity_decision", "opportunity_reason", "policy_hash"):
        if stored.get(advanced) is not None:
            problems.append(f"{advanced} is advanced and non-null")
    for stamp in ("created_at", "updated_at"):
        try:
            require_rfc3339_timestamp(stored.get(stamp), f"stored {stamp}")
        except ProjectionConflict as exc:
            problems.append(str(exc))
    return problems

@dataclass(frozen=True)
class AcceptedScoreClassification:
    """Terminal classification of one accepted assessment row family."""

    action: str  # exactly "insert_required" or "reuse"
    projection: AcceptedScoreProjection | None

def classify_accepted_score(
    connection: sqlite3.Connection,
    *,
    result: ScoreResult,
    url: str,
    title: str,
    company: str,
    extraction_confidence: float | None,
) -> AcceptedScoreClassification:
    """Classify the accepted assessment on a caller-owned connection.

    No timestamp input/generation, connect, transaction control,
    schema/migration work, or DML happens here. One exact read of the
    full explicit column list feeds the canonical comparator; absent
    rows classify ``insert_required`` with no projection and present
    rows reuse only when every process-owned field, advanced NULLs,
    scored state, strict stored RFC3339 timestamps and exact row shape
    agree, yielding the exact durable projection. SQL errors propagate
    unchanged and caller row_factory stays untouched.
    """

    (
        url_value, title_value, company_value,
        opportunity, fit, final_score, confidence, payload, digest,
    ) = canonical_accepted_score_fields(
        result=result, url=url, title=title, company=company,
        extraction_confidence=extraction_confidence,
    )
    row = connection.execute(
        f"""SELECT {','.join(_SCORE_ROW_COLUMNS)}
            FROM assessments WHERE profile_id=? AND job_key=?""",
        (result.profile_id, result.job_key),
    ).fetchone()
    if row is None:
        return AcceptedScoreClassification(
            action="insert_required", projection=None
        )
    values = _row_to_columns(row, _SCORE_ROW_COLUMNS)
    problems = _score_row_problems(
        values,
        expected_profile_id=result.profile_id,
        expected_job_key=result.job_key,
        expected_url=url_value,
        expected_title=title_value,
        expected_company=company_value,
        expected_opportunity=opportunity,
        expected_fit=fit,
        expected_final=final_score,
        expected_status=result.fit_status.value,
        expected_confidence=confidence,
        expected_payload=payload,
        expected_digest=digest,
    )
    if problems:
        raise ProjectionConflict(
            "assessment projection differs from the accepted score: "
            + "; ".join(problems)
        )
    return AcceptedScoreClassification(
        action="reuse",
        projection=AcceptedScoreProjection(
            **{k: values[k] for k in _SCORE_PROJECTION_COLUMNS}
        ),
    )

def plan_accepted_score(
    connection: sqlite3.Connection,
    *,
    result: ScoreResult,
    url: str,
    title: str,
    company: str,
    extraction_confidence: float | None,
    accepted_at: str,
) -> ScoreReadPlan:
    """Read-plan preserving the exact current precedence.

    ``accepted_at`` validates strictly BEFORE any classifier or SQL work;
    classification reuses the accepted canonical validation/comparator.
    ``insert_required`` yields the existing exact insert plan with
    created_at == updated_at == accepted_at; ``reuse`` carries the exact
    durable timestamps of the classified projection. Public types, error
    behavior, byte identity, and CAS behavior are unchanged.
    """

    require_rfc3339_timestamp(accepted_at, "accepted_at")
    classification = classify_accepted_score(
        connection,
        result=result,
        url=url,
        title=title,
        company=company,
        extraction_confidence=extraction_confidence,
    )
    if classification.action == "reuse":
        assert classification.projection is not None
        _, _, _, _, _, _, _, payload, digest = canonical_accepted_score_fields(
            result=result, url=url, title=title, company=company,
            extraction_confidence=extraction_confidence,
        )
        reuse = ScoreReusePlan(
            profile_id=result.profile_id,
            job_key=result.job_key,
            score_payload_hash=digest,
            created_at=classification.projection.created_at,
            updated_at=classification.projection.updated_at,
        )
        return ScoreReadPlan(action="reuse", insert=None, reuse=reuse)
    assert classification.projection is None
    (
        url_value, title_value, company_value,
        opportunity, fit, final_score, confidence, payload, digest,
    ) = canonical_accepted_score_fields(
        result=result, url=url, title=title, company=company,
        extraction_confidence=extraction_confidence,
    )
    insert = ScoreInsertPlan(
        profile_id=result.profile_id,
        job_key=result.job_key,
        url=url_value,
        title=title_value,
        company=company_value,
        opportunity=opportunity,
        fit=fit,
        final_score=final_score,
        extraction_confidence=confidence,
        score_payload_json=payload,
        score_payload_hash=digest,
        created_at=accepted_at,
    )
    return ScoreReadPlan(action="insert", insert=insert, reuse=None)

def execute_score_insert(
    connection: sqlite3.Connection, plan: ScoreInsertPlan
) -> AcceptedScoreProjection:
    """One explicit INSERT plus exact reread; integrity maps to conflict."""

    cursor = connection.execute(
        """INSERT INTO assessments(
             profile_id,job_key,url,title,company,
             opportunity,fit,final_score,
             fit_status,extraction_confidence,
             score_payload_json,score_payload_hash,
             state,created_at,updated_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            plan.profile_id,
            plan.job_key,
            plan.url,
            plan.title,
            plan.company,
            plan.opportunity,
            plan.fit,
            plan.final_score,
            "uncalibrated",
            plan.extraction_confidence,
            plan.score_payload_json,
            plan.score_payload_hash,
            "scored",
            plan.created_at,
            plan.created_at,
        ),
    )
    if cursor.rowcount != 1:
        raise ProjectionConflict("score insert did not land exactly one row")
    return _reread_accepted_score(connection, plan)

def _reread_accepted_score(
    connection: sqlite3.Connection, plan: ScoreInsertPlan
) -> AcceptedScoreProjection:
    row = connection.execute(
        f"""SELECT {','.join(_SCORE_ROW_COLUMNS)}
            FROM assessments WHERE profile_id=? AND job_key=?""",
        (plan.profile_id, plan.job_key),
    ).fetchone()
    if row is None:
        raise ProjectionConflict("score reread found no row")
    problems = _score_row_problems(
        row,
        expected_profile_id=plan.profile_id,
        expected_job_key=plan.job_key,
        expected_url=plan.url,
        expected_title=plan.title,
        expected_company=plan.company,
        expected_opportunity=plan.opportunity,
        expected_fit=plan.fit,
        expected_final=plan.final_score,
        expected_status="uncalibrated",
        expected_confidence=plan.extraction_confidence,
        expected_payload=plan.score_payload_json,
        expected_digest=plan.score_payload_hash,
    )
    if problems:
        raise ProjectionConflict("; ".join(problems))
    values = _row_to_columns(row, _SCORE_ROW_COLUMNS)
    projection = AcceptedScoreProjection(
        **{k: values[k] for k in _SCORE_PROJECTION_COLUMNS}
    )
    if projection.created_at != plan.created_at or projection.updated_at != plan.created_at:
        raise ProjectionConflict(
            "inserted timestamps must equal the accepted instant exactly"
        )
    return projection

def cas_accepted_score(
    connection: sqlite3.Connection,
    *,
    result: ScoreResult,
    url: str,
    title: str,
    company: str,
    extraction_confidence: float | None,
    accepted_at: str,
) -> AcceptedScoreOutcome:
    """Plan then conditionally insert; both paths end in an exact reread."""

    plan = plan_accepted_score(
        connection,
        result=result,
        url=url,
        title=title,
        company=company,
        extraction_confidence=extraction_confidence,
        accepted_at=accepted_at,
    )
    if plan.action == "insert":
        try:
            projection = execute_score_insert(connection, plan.insert)
        except sqlite3.IntegrityError as exc:
            raise ProjectionConflict(
                f"score insert lost an integrity race: {exc}"
            ) from exc
        return AcceptedScoreOutcome(action="insert", plan=plan, projection=projection)
    (
        url_value, title_value, company_value,
        opportunity, fit, final_score, confidence, payload, digest,
    ) = canonical_accepted_score_fields(
        result=result, url=url, title=title, company=company,
        extraction_confidence=extraction_confidence,
    )
    row = connection.execute(
        f"""SELECT {','.join(_SCORE_ROW_COLUMNS)}
            FROM assessments WHERE profile_id=? AND job_key=?""",
        (result.profile_id, result.job_key),
    ).fetchone()
    if row is None:
        raise ProjectionConflict("reuse reread found no row")
    problems = _score_row_problems(
        row,
        expected_profile_id=result.profile_id,
        expected_job_key=result.job_key,
        expected_url=url_value,
        expected_title=title_value,
        expected_company=company_value,
        expected_opportunity=opportunity,
        expected_fit=fit,
        expected_final=final_score,
        expected_status=result.fit_status.value,
        expected_confidence=confidence,
        expected_payload=payload,
        expected_digest=digest,
    )
    if problems:
        raise ProjectionConflict(
            "assessment drifted between plan and reread: "
            + "; ".join(problems)
        )
    values = _row_to_columns(row, _SCORE_ROW_COLUMNS)
    if (
        values["created_at"] != plan.reuse.created_at
        or values["updated_at"] != plan.reuse.updated_at
    ):
        raise ProjectionConflict(
            "reused timestamps drifted between plan and reread"
        )
    projection = AcceptedScoreProjection(
        **{k: values[k] for k in _SCORE_PROJECTION_COLUMNS}
    )
    return AcceptedScoreOutcome(action="reuse", plan=plan, projection=projection)

@dataclass(frozen=True)
class ProcessingEventInsertPlan:
    event_id: int
    profile_id: str
    job_key: str
    event_type: str
    actor_kind: str
    payload_json: str
    idempotency_key: str
    created_at: str

@dataclass(frozen=True)
class ProcessingEventReadPlan:
    action: str  # exactly "insert" or "reuse"
    insert: ProcessingEventInsertPlan | None
    reused_event_id: int | None

@dataclass(frozen=True)
class ProcessingEventProjection:
    event_id: int
    profile_id: str
    job_key: str
    event_type: str
    actor_kind: str
    payload_json: str
    idempotency_key: str
    created_at: str

def _event_row_problems(values: dict, expected: dict) -> list[str]:
    """Exact column/primitive comparison for any event reread."""

    problems: list[str] = []
    malformed: set[str] = set()
    try:
        stored_id = values["id"]
        if isinstance(stored_id, bool) or not isinstance(stored_id, int):
            problems.append("stored id must be an integer without bool")
            malformed.add("id")
        for column in (
            "profile_id", "job_key", "event_type", "actor_kind",
            "payload_json", "idempotency_key", "created_at",
        ):
            if not isinstance(values.get(column), str):
                problems.append(f"stored {column} must be a string")
                malformed.add(column)
        created_at = values.get("created_at")
        if isinstance(created_at, str):
            try:
                require_rfc3339_timestamp(created_at, "stored created_at")
            except ProjectionConflict as exc:
                problems.append(str(exc))
                malformed.add("created_at")
    except ProjectionConflict as exc:
        problems.append(str(exc))
    except (TypeError, KeyError) as exc:
        return [f"malformed event row: {exc}"]
    for column, wanted in expected.items():
        if column in malformed:
            continue
        if values.get(column) != wanted:
            problems.append(f"stored {column} differs from the exact authority")
    return problems

@dataclass(frozen=True)
class ProcessingEventOutcome:
    action: str  # exactly "insert" or "reuse"
    plan: ProcessingEventReadPlan
    projection: ProcessingEventProjection | None

def _canonical_payload_or_conflict(payload_json: Any) -> str:
    if not isinstance(payload_json, str):
        raise ProjectionConflict("payload_json must be canonical JSON text")

    def _reject_constant(name: str) -> None:
        raise ValueError(name)

    try:
        parsed = json.loads(
            payload_json, parse_constant=_reject_constant
        )
        reserialized = json.dumps(
            parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    except (ValueError, TypeError) as exc:
        raise ProjectionConflict(
            f"payload_json is not strict canonical JSON: {exc}"
        ) from exc
    if reserialized != payload_json:
        raise ProjectionConflict(
            "payload_json must already be canonical compact sorted JSON"
        )
    return payload_json

def plan_processing_event(
    connection: sqlite3.Connection,
    *,
    profile_id: str,
    job_key: str,
    event_type: str,
    actor_kind: str,
    payload_json: str,
    idempotency_key: str,
    created_at: str,
    event_id: int,
) -> ProcessingEventReadPlan:
    """Read-plan for the closed generic event families (C1 seam extension)."""

    if event_type not in _EVENT_TYPES:
        raise ProjectionConflict(
            "event_type must be one of the closed contracted event types"
        )
    if actor_kind != "deterministic":
        raise ProjectionConflict("actor_kind must be exactly 'deterministic'")
    require_exact_profile_id(profile_id)
    _require_text(job_key, "job_key", 3, 256)
    if isinstance(event_id, bool) or not isinstance(event_id, int):
        raise ProjectionConflict("event_id must be an integer without bool")
    if not 1 <= event_id <= 2**63 - 1:
        raise ProjectionConflict(
            "event_id must be a positive signed 64-bit integer"
        )
    _canonical_payload_or_conflict(payload_json)
    key_bytes = (
        idempotency_key.encode("utf-8")
        if isinstance(idempotency_key, str) else b""
    )
    if not key_bytes or len(key_bytes) > _MAX_IDEMPOTENCY_KEY_BYTES:
        raise ProjectionConflict(
            "idempotency_key must be nonempty ASCII within 512 bytes"
        )
    if not key_bytes.isascii():
        raise ProjectionConflict("idempotency_key must be ASCII")
    require_rfc3339_timestamp(created_at, "created_at")
    rows = connection.execute(
        f"""SELECT {','.join(_EVENT_PROJECTION_COLUMNS)}
            FROM assessment_events
            WHERE profile_id=? AND job_key=? AND event_type=?""",
        (profile_id, job_key, event_type),
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict(
            "multiple matching events refuse; at most one may exist"
        )
    if not rows:
        insert = ProcessingEventInsertPlan(
            event_id=event_id,
            profile_id=profile_id,
            job_key=job_key,
            event_type=event_type,
            actor_kind=actor_kind,
            payload_json=payload_json,
            idempotency_key=idempotency_key,
            created_at=created_at,
        )
        return ProcessingEventReadPlan(
            action="insert", insert=insert, reused_event_id=None
        )
    row = _row_to_columns(rows[0], _EVENT_PROJECTION_COLUMNS)
    expected = {
        "id": event_id,
        "profile_id": profile_id,
        "job_key": job_key,
        "event_type": event_type,
        "actor_kind": actor_kind,
        "payload_json": payload_json,
        "idempotency_key": idempotency_key,
        "created_at": created_at,
    }
    problems = _event_row_problems(row, expected)
    if problems:
        raise ProjectionConflict(
            "existing event differs from the exact planned event: "
            + "; ".join(problems)
        )
    return ProcessingEventReadPlan(
        action="reuse", insert=None, reused_event_id=row["id"]
    )

def execute_processing_event_insert(
    connection: sqlite3.Connection, plan: ProcessingEventInsertPlan
) -> ProcessingEventProjection:
    """One explicit-ID INSERT, lastrowid proof, and exact reread."""

    cursor = connection.execute(
        f"""INSERT INTO assessment_events(
             {','.join(_EVENT_PROJECTION_COLUMNS)}
           ) VALUES(?,?,?,?,?,?,?,?)""",
        (
            plan.event_id,
            plan.profile_id,
            plan.job_key,
            plan.event_type,
            plan.actor_kind,
            plan.payload_json,
            plan.idempotency_key,
            plan.created_at,
        ),
    )
    if cursor.lastrowid != plan.event_id:
        raise ProjectionConflict(
            "inserted event id differs from the planned explicit id"
        )
    row = connection.execute(
        f"""SELECT {','.join(_EVENT_PROJECTION_COLUMNS)}
            FROM assessment_events WHERE id=?""",
        (plan.event_id,),
    ).fetchone()
    if row is None:
        raise ProjectionConflict("event reread found no row")
    values = _row_to_columns(row, _EVENT_PROJECTION_COLUMNS)
    expected = {
        "id": plan.event_id,
        "profile_id": plan.profile_id,
        "job_key": plan.job_key,
        "event_type": plan.event_type,
        "actor_kind": plan.actor_kind,
        "payload_json": plan.payload_json,
        "idempotency_key": plan.idempotency_key,
        "created_at": plan.created_at,
    }
    problems = _event_row_problems(values, expected)
    if problems:
        raise ProjectionConflict(
            "event insert reread drifted: " + "; ".join(problems)
        )
    return ProcessingEventProjection(
        event_id=values["id"],
        profile_id=values["profile_id"],
        job_key=values["job_key"],
        event_type=values["event_type"],
        actor_kind=values["actor_kind"],
        payload_json=values["payload_json"],
        idempotency_key=values["idempotency_key"],
        created_at=values["created_at"],
    )

def cas_processing_event(
    connection: sqlite3.Connection,
    *,
    profile_id: str,
    job_key: str,
    event_type: str,
    actor_kind: str,
    payload_json: str,
    idempotency_key: str,
    created_at: str,
    event_id: int,
) -> ProcessingEventOutcome:
    """Plan then conditionally insert; reuse performs zero DML."""

    plan = plan_processing_event(
        connection,
        profile_id=profile_id,
        job_key=job_key,
        event_type=event_type,
        actor_kind=actor_kind,
        payload_json=payload_json,
        idempotency_key=idempotency_key,
        created_at=created_at,
        event_id=event_id,
    )
    if plan.action == "insert":
        try:
            projection = execute_processing_event_insert(connection, plan.insert)
        except sqlite3.IntegrityError as exc:
            raise ProjectionConflict(
                f"event insert lost an integrity race: {exc}"
            ) from exc
        return ProcessingEventOutcome(
            action="insert", plan=plan, projection=projection
        )
    row = connection.execute(
        f"""SELECT {','.join(_EVENT_PROJECTION_COLUMNS)}
            FROM assessment_events WHERE id=?""",
        (plan.reused_event_id,),
    ).fetchone()
    if row is None:
        raise ProjectionConflict("event reuse reread found no row")
    values = _row_to_columns(row, _EVENT_PROJECTION_COLUMNS)
    expected = {
        "id": event_id,
        "profile_id": profile_id,
        "job_key": job_key,
        "event_type": event_type,
        "actor_kind": actor_kind,
        "payload_json": payload_json,
        "idempotency_key": idempotency_key,
        "created_at": created_at,
    }
    problems = _event_row_problems(values, expected)
    if problems:
        raise ProjectionConflict(
            "event drifted between plan and reread: " + "; ".join(problems)
        )
    projection = ProcessingEventProjection(
        event_id=values["id"],
        profile_id=values["profile_id"],
        job_key=values["job_key"],
        event_type=values["event_type"],
        actor_kind=values["actor_kind"],
        payload_json=values["payload_json"],
        idempotency_key=values["idempotency_key"],
        created_at=values["created_at"],
    )
    return ProcessingEventOutcome(
        action="reuse", plan=plan, projection=projection
    )

@dataclass(frozen=True)
class ProcessingScoreEventClassification:
    """Presence-only classification of processing_score_accepted events."""

    action: str  # exactly "insert_required" or "existing"
    count: int

def classify_processing_score_event(
    connection: sqlite3.Connection,
    *,
    profile_id: str,
    job_key: str,
    event_type: str = _PROCESSING_SCORE_ACCEPTED,
) -> ProcessingScoreEventClassification:
    """Presence-only event family classifier on a caller-owned connection.

    Validates the exact profile/job identity BEFORE any SQL, queries ALL
    rows with the exact explicit event column list for this profile/job
    and the supplied contracted ``event_type`` (default preserves the C1
    processing family), and shape-validates every returned row through the
    canonical row mapper only. Event contents are never authenticated; no
    prospective id/timestamp/actor/payload/key is accepted. Zero rows
    classify insert_required with count 0; one or more rows classify
    existing with the exact count. SQL errors propagate unchanged and caller
    row_factory stays untouched.
    """

    if event_type not in _EVENT_TYPES:
        raise ProjectionConflict(
            "event_type must be one of the closed contracted event types"
        )
    require_exact_profile_id(profile_id)
    _require_text(job_key, "job_key", 3, 256)
    rows = connection.execute(
        f"""SELECT {','.join(_EVENT_PROJECTION_COLUMNS)}
            FROM assessment_events
            WHERE profile_id=? AND job_key=? AND event_type=?""",
        (profile_id, job_key, event_type),
    ).fetchall()
    for row in rows:
        _row_to_columns(row, _EVENT_PROJECTION_COLUMNS)
    if not rows:
        return ProcessingScoreEventClassification(
            action="insert_required", count=0
        )
    return ProcessingScoreEventClassification(
        action="existing", count=len(rows)
    )


class AssessmentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.data_home = (
            self.path.parent.parent
            if self.path.parent.name == "state"
            else self.path.parent
        ).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(employer_research_queue)"
                )
            }
            if "refresh_event_id" not in columns:
                connection.execute(
                    "ALTER TABLE employer_research_queue ADD COLUMN "
                    "refresh_event_id INTEGER REFERENCES assessment_events(id) "
                    "ON DELETE RESTRICT"
                )
            if "refresh_bridge_sha256" not in columns:
                connection.execute(
                    "ALTER TABLE employer_research_queue ADD COLUMN "
                    "refresh_bridge_sha256 TEXT"
                )
            connection.executescript(_REFRESH_QUEUE_IMMUTABILITY_TRIGGER)

    def connect(self) -> sqlite3.Connection:
        with owner_private_umask():
            connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with owner_private_umask():
            connection = self.connect()
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with owner_private_umask():
            connection = self.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def upsert_score(
        self,
        result: ScoreResult,
        *,
        url: str,
        title: str,
        company: str,
        extraction_confidence: float | None,
    ) -> None:
        validate_profile_id(result.profile_id)
        payload = json.dumps(asdict(result), ensure_ascii=False, sort_keys=True, default=str)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO assessments(
                     profile_id,job_key,url,title,company,opportunity,fit,final_score,fit_status,
                     extraction_confidence,score_payload_json,score_payload_hash
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(profile_id,job_key) DO UPDATE SET
                     url=excluded.url,title=excluded.title,company=excluded.company,
                     opportunity=excluded.opportunity,fit=excluded.fit,
                     final_score=excluded.final_score,fit_status=excluded.fit_status,
                     extraction_confidence=excluded.extraction_confidence,
                     score_payload_json=excluded.score_payload_json,
                     score_payload_hash=excluded.score_payload_hash,updated_at=CURRENT_TIMESTAMP""",
                (
                    result.profile_id,
                    result.job_key,
                    url,
                    title,
                    company,
                    result.opportunity,
                    result.fit,
                    result.final,
                    result.fit_status.value,
                    extraction_confidence,
                    payload,
                    digest,
                ),
            )
            connection.execute(
                """INSERT OR IGNORE INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    result.profile_id,
                    result.job_key,
                    "score_snapshot_imported",
                    "deterministic",
                    json.dumps({"score_payload_hash": digest}, sort_keys=True),
                    f"score:{result.profile_id}:{result.job_key}:{digest}",
                ),
            )

    def assessment(self, profile_id: str, job_key: str) -> sqlite3.Row:
        validate_profile_id(profile_id)
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
        if row is None:
            raise KeyError((profile_id, job_key))
        return row

    def ranked(self, profile_id: str) -> list[sqlite3.Row]:
        validate_profile_id(profile_id)
        with self.connection() as connection:
            return connection.execute(
                """SELECT * FROM assessments WHERE profile_id=?
                   ORDER BY final_score DESC,opportunity DESC,job_key""",
                (profile_id,),
            ).fetchall()

    def apply_opportunity_gate(
        self,
        *,
        profile_id: str,
        job_key: str,
        passed: bool,
        reason: str,
        policy_hash: str,
        priority: int | None,
    ) -> None:
        decision = "pass" if passed else "reject"
        state = "employer_research_queued" if passed else "opportunity_rejected"
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT score_payload_hash FROM assessments WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
            if current is None:
                raise KeyError((profile_id, job_key))
            if passed and priority is None:
                raise ValueError("passed opportunity requires research priority")
            connection.execute(
                """UPDATE assessments SET state=?,opportunity_decision=?,opportunity_reason=?,
                     policy_hash=?,updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (state, decision, reason, policy_hash, profile_id, job_key),
            )
            event_key = (
                f"opportunity:{profile_id}:{job_key}:{current['score_payload_hash']}:{policy_hash}"
            )
            connection.execute(
                """INSERT OR IGNORE INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "opportunity_gate_decided",
                    "deterministic",
                    json.dumps({"decision": decision, "reason": reason}, sort_keys=True),
                    event_key,
                ),
            )
            if passed:
                connection.execute(
                    """INSERT INTO employer_research_queue(profile_id,job_key,priority)
                       VALUES(?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                       priority=excluded.priority,refresh_event_id=NULL,
                       refresh_bridge_sha256=NULL,
                       updated_at=CURRENT_TIMESTAMP""",
                    (profile_id, job_key, priority),
                )
            else:
                connection.execute(
                    """DELETE FROM employer_research_queue
                       WHERE profile_id=? AND job_key=? AND status='queued'""",
                    (profile_id, job_key),
                )

    def promote_processing_gate(
        self,
        *,
        profile_id: str,
        job_key: str,
        score: dict[str, object],
        policy_hash: str,
        processing_receipt_sha256: str,
        processing_result_sha256: str,
        source_content_sha256: str,
        authority_sha256: str,
        processing_config_sha256: str,
        track: str,
        receipt_bytes: bytes,
        receipt_sha256: str,
    ) -> bool:
        """Atomically bind one current processing result to the handoff gate."""

        try:
            receipt = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("processing promotion receipt is invalid JSON") from exc
        canonical = json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        body = dict(receipt) if isinstance(receipt, dict) else {}
        body.pop("receipt_sha256", None)
        expected_receipt_sha = hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        policy = receipt.get("policy") if isinstance(receipt, dict) else None
        binding = receipt.get("binding") if isinstance(receipt, dict) else None
        if (
            receipt_bytes != canonical
            or receipt.get("schema_version")
            != "market-aligner.assessment-promotion-receipt.v1"
            or receipt.get("decision") != "pass"
            or receipt.get("profile_id") != profile_id
            or receipt.get("job_key") != job_key
            or receipt.get("policy_sha256") != policy_hash
            or receipt.get("receipt_sha256") != receipt_sha256
            or receipt_sha256 != expected_receipt_sha
            or not isinstance(policy, dict)
            or hashlib.sha256(
                json.dumps(
                    policy,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            != policy_hash
            or not isinstance(binding, dict)
            or hashlib.sha256(
                json.dumps(
                    binding,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            != receipt.get("binding_sha256")
            or binding.get("processing_receipt_sha256")
            != processing_receipt_sha256
            or binding.get("processing_result_sha256") != processing_result_sha256
            or binding.get("source_content_sha256") != source_content_sha256
            or binding.get("evidence_authority_sha256") != authority_sha256
            or binding.get("processing_config_sha256")
            != processing_config_sha256
            or binding.get("track") != track
        ):
            raise ValueError("processing promotion receipt bindings differ")
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT * FROM assessments WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
            if current is None:
                raise KeyError((profile_id, job_key))
            if receipt.get("score_payload_hash") != current["score_payload_hash"]:
                raise ValueError("processing promotion score receipt differs")
            expected = {
                "fit": current["fit"],
                "opportunity": current["opportunity"],
                "final": current["final_score"],
                "fit_status": current["fit_status"],
            }
            if any(score.get(key) != value for key, value in expected.items()):
                raise ValueError("processing promotion score differs from assessment state")
            research_priority = 1_000_000 + round(
                float(current["opportunity"]) * 100_000
            )
            existing = connection.execute(
                "SELECT * FROM assessment_promotions WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
            if existing is not None:
                if (
                    existing["receipt_sha256"] != receipt_sha256
                    or bytes(existing["receipt_bytes"]) != receipt_bytes
                    or current["opportunity_decision"] != "pass"
                    or current["policy_hash"] != policy_hash
                ):
                    raise ValueError("processing promotion conflicts with sealed prior promotion")
                connection.execute(
                    """INSERT INTO employer_research_queue(profile_id,job_key,priority)
                       VALUES(?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                       priority=excluded.priority,refresh_event_id=NULL,
                       refresh_bridge_sha256=NULL,
                       updated_at=CURRENT_TIMESTAMP""",
                    (profile_id, job_key, research_priority),
                )
                return False
            connection.execute(
                """INSERT INTO assessment_promotions(
                     profile_id,job_key,track,authority_sha256,source_content_sha256,
                     processing_config_sha256,processing_receipt_sha256,
                     processing_result_sha256,score_payload_hash,policy_hash,
                     receipt_bytes,receipt_sha256
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    track,
                    authority_sha256,
                    source_content_sha256,
                    processing_config_sha256,
                    processing_receipt_sha256,
                    processing_result_sha256,
                    current["score_payload_hash"],
                    policy_hash,
                    sqlite3.Binary(receipt_bytes),
                    receipt_sha256,
                ),
            )
            connection.execute(
                """UPDATE assessments SET state='opportunity_promoted',
                     opportunity_decision='pass',opportunity_reason=?,policy_hash=?,
                     updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (
                    f"processing-promotion:{receipt_sha256}",
                    policy_hash,
                    profile_id,
                    job_key,
                ),
            )
            connection.execute(
                """INSERT INTO employer_research_queue(profile_id,job_key,priority)
                   VALUES(?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                   priority=excluded.priority,refresh_event_id=NULL,
                   refresh_bridge_sha256=NULL,
                   updated_at=CURRENT_TIMESTAMP""",
                (profile_id, job_key, research_priority),
            )
            connection.execute(
                """INSERT INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "processing_assessment_promoted",
                    "deterministic",
                    json.dumps(
                        {
                            "policy_hash": policy_hash,
                            "processing_receipt_sha256": processing_receipt_sha256,
                            "processing_result_sha256": processing_result_sha256,
                            "receipt_sha256": receipt_sha256,
                        },
                        sort_keys=True,
                    ),
                    f"processing-promotion:{profile_id}:{job_key}:{receipt_sha256}",
                ),
            )
            return True

    def processing_promotion(self, profile_id: str, job_key: str) -> sqlite3.Row:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM assessment_promotions WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
        if row is None:
            raise KeyError((profile_id, job_key))
        return row

    def enqueue_research(self, profile_id: str, job_key: str, priority: int) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO employer_research_queue(profile_id,job_key,priority) VALUES(?,?,?)",
                (profile_id, job_key, priority),
            )

    def claim_research(
        self,
        worker_id: str,
        lease_seconds: int = 900,
        *,
        profile_id: str | None = None,
        job_key: str | None = None,
        require_refresh_bridge: bool = False,
        _preview_without_lease: bool = False,
    ) -> ResearchTask | None:
        if (profile_id is None) != (job_key is None):
            raise ValueError("research claim scope requires both profile_id and job_key")
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=max(1, lease_seconds))
        with self.transaction() as connection:
            scope = ""
            parameters: tuple[object, ...] = ()
            if profile_id is not None and job_key is not None:
                scope = " AND q.profile_id=? AND q.job_key=?"
                parameters = (profile_id, job_key)
            if require_refresh_bridge:
                scope += (
                    " AND q.refresh_event_id IS NOT NULL"
                    " AND q.refresh_bridge_sha256 IS NOT NULL"
                    " AND e.id=q.refresh_event_id"
                    " AND e.event_type='employer_research_collection_refresh_queued'"
                )
            row = connection.execute(
                """SELECT q.profile_id,q.job_key,a.title,a.company,a.url,a.opportunity,
                          q.priority,q.attempts,p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256,
                          q.refresh_event_id,q.refresh_bridge_sha256,
                          e.event_type AS refresh_event_type,
                          e.actor_kind AS refresh_actor_kind,
                          e.payload_json AS refresh_payload_json,
                          e.idempotency_key AS refresh_event_idempotency_key,
                          d.dossier_hash AS refresh_current_dossier_hash,
                          d.dossier_json AS refresh_current_dossier_json
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   LEFT JOIN assessment_events e
                     ON e.id=q.refresh_event_id
                    AND e.profile_id=q.profile_id AND e.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   WHERE ((q.status='queued' AND datetime(q.available_at)<=CURRENT_TIMESTAMP)
                      OR (q.status='leased' AND datetime(q.lease_until)<CURRENT_TIMESTAMP))"""
                + scope
                + " ORDER BY q.priority DESC,a.opportunity DESC,q.queued_at LIMIT 1",
                parameters,
            ).fetchone()
            if row is None:
                return None
            if not _preview_without_lease:
                connection.execute(
                    """UPDATE employer_research_queue SET status='leased',attempts=attempts+1,
                         lease_owner=?,lease_until=?,updated_at=CURRENT_TIMESTAMP
                       WHERE profile_id=? AND job_key=?""",
                    (worker_id, lease_until.isoformat(), row["profile_id"], row["job_key"]),
                )
            values = dict(row)
            refresh_event_id = values.pop("refresh_event_id")
            refresh_event_type = values.pop("refresh_event_type")
            refresh_actor_kind = values.pop("refresh_actor_kind")
            refresh_payload_json = values.pop("refresh_payload_json")
            refresh_event_idempotency_key = values.pop(
                "refresh_event_idempotency_key"
            )
            refresh_current_dossier_hash = values.pop(
                "refresh_current_dossier_hash"
            )
            refresh_current_dossier_json = values.pop(
                "refresh_current_dossier_json"
            )
            refresh_values = {
                "refresh_event_id": refresh_event_id,
                "refresh_event_idempotency_key": None,
                "refresh_receipt_sha256": None,
                "refresh_receipt_file_sha256": None,
                "refresh_transition_sha256": None,
                "refresh_id": None,
                "refresh_context_sha256": None,
                "refresh_operation_id": None,
                "refresh_legacy_content_sha256": None,
                "refresh_canonical_content_sha256": None,
                "refresh_raw_object_sha256": None,
                "refresh_fetched_at": None,
                "refresh_promotion_receipt_sha256": None,
                "refresh_prior_dossier_sha256": None,
            }
            if refresh_event_id is not None:
                try:
                    payload = json.loads(str(refresh_payload_json))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError("research refresh event payload is invalid") from exc
                expected_keys = {
                    "collection_context_sha256",
                    "collection_operation_id",
                    "collection_receipt_file_sha256",
                    "collection_receipt_sha256",
                    "collection_refresh_id",
                    "collection_transition_sha256",
                    "new_fetched_at",
                    "new_raw_object_sha256",
                    "old_canonical_content_sha256",
                    "old_collector_content_sha256",
                    "prior_dossier_hash",
                    "promotion_receipt_sha256",
                    "refresh_bridge_sha256",
                    "source_content_sha256",
                }
                if (
                    refresh_event_type
                    != "employer_research_collection_refresh_queued"
                    or refresh_actor_kind != "deterministic"
                    or not isinstance(payload, dict)
                    or set(payload) != expected_keys
                    or payload["source_content_sha256"]
                    != values["source_content_sha256"]
                    or not research_refresh_preserves_source_authority(
                        source_content_sha256=values["source_content_sha256"],
                        old_collector_content_sha256=payload[
                            "old_collector_content_sha256"
                        ],
                        old_canonical_content_sha256=payload[
                            "old_canonical_content_sha256"
                        ],
                    )
                    or payload["promotion_receipt_sha256"]
                    != values["promotion_receipt_sha256"]
                    or refresh_event_idempotency_key
                    != (
                        f"research-collection-refresh:{values['profile_id']}:"
                        f"{values['job_key']}:"
                        f"{payload['collection_transition_sha256']}"
                    )
                    or payload["prior_dossier_hash"]
                    != refresh_current_dossier_hash
                    or not isinstance(refresh_current_dossier_json, str)
                    or hashlib.sha256(
                        refresh_current_dossier_json.encode("utf-8")
                    ).hexdigest()
                    != refresh_current_dossier_hash
                    or payload["refresh_bridge_sha256"]
                    != values["refresh_bridge_sha256"]
                    or research_refresh_bridge_sha256(
                        event_type=str(refresh_event_type),
                        actor_kind=str(refresh_actor_kind),
                        idempotency_key=str(refresh_event_idempotency_key),
                        payload=payload,
                    )
                    != values["refresh_bridge_sha256"]
                ):
                    raise ValueError("research refresh event differs from promotion")
                refresh_values.update(
                    refresh_event_idempotency_key=refresh_event_idempotency_key,
                    refresh_receipt_sha256=payload["collection_receipt_sha256"],
                    refresh_receipt_file_sha256=payload[
                        "collection_receipt_file_sha256"
                    ],
                    refresh_transition_sha256=payload[
                        "collection_transition_sha256"
                    ],
                    refresh_id=payload["collection_refresh_id"],
                    refresh_context_sha256=payload["collection_context_sha256"],
                    refresh_operation_id=payload["collection_operation_id"],
                    refresh_legacy_content_sha256=payload[
                        "old_collector_content_sha256"
                    ],
                    refresh_canonical_content_sha256=payload[
                        "old_canonical_content_sha256"
                    ],
                    refresh_raw_object_sha256=payload["new_raw_object_sha256"],
                    refresh_fetched_at=payload["new_fetched_at"],
                    refresh_promotion_receipt_sha256=payload[
                        "promotion_receipt_sha256"
                    ],
                    refresh_prior_dossier_sha256=payload["prior_dossier_hash"],
                )
            values["vacancy_snapshot_sha256"] = _vacancy_snapshot_sha256(values)
            values.update(refresh_values)
            return ResearchTask(**values)

    def preview_refresh_research(
        self, profile_id: str, job_key: str
    ) -> ResearchTask | None:
        """Resolve one exact available refresh task without changing its lease."""

        return self.claim_research(
            "selector-review-preview",
            profile_id=profile_id,
            job_key=job_key,
            require_refresh_bridge=True,
            _preview_without_lease=True,
        )

    def _has_current_v2_evidence(self, row: sqlite3.Row) -> bool:
        try:
            document = json.loads(row["dossier_json"])
            expected_snapshot = _vacancy_snapshot_sha256(dict(row))
            if (
                not isinstance(document, dict)
                or document.get("schema_version")
                != "market-aligner.employer-dossier.v2"
                or hashlib.sha256(row["dossier_json"].encode("utf-8")).hexdigest()
                != row["dossier_hash"]
                or row["evidence_dossier_hash"] != row["dossier_hash"]
                or row["evidence_schema_version"]
                != "market-aligner.research-store-binding.v2"
                or row["evidence_source_content_sha256"]
                != row["source_content_sha256"]
                or row["evidence_vacancy_snapshot_sha256"] != expected_snapshot
                or row["evidence_promotion_receipt_sha256"]
                != row["promotion_receipt_sha256"]
                or document.get("source_content_sha256")
                != row["source_content_sha256"]
                or document.get("vacancy_snapshot_sha256") != expected_snapshot
                or document.get("promotion_receipt_sha256")
                != row["promotion_receipt_sha256"]
                or document.get("canonical_vacancy_object_sha256")
                != row["canonical_vacancy_object_sha256"]
            ):
                return False
            binding = ResearchEvidenceBinding(
                row["evidence_dossier_hash"],
                row["evidence_source_content_sha256"],
                row["evidence_vacancy_snapshot_sha256"],
                row["evidence_promotion_receipt_sha256"],
                row["canonical_vacancy_object_sha256"],
                row["semantic_receipt_sha256"],
                row["receipt_file_sha256"],
                row["archive_root_identity"],
                row["archive_root_policy_sha256"],
                row["receipt_relative_path"],
                row["evidence_schema_version"],
            )
            binding.validate()
            root = (self.data_home / binding.archive_root_identity).resolve()
            if self.data_home not in root.parents or root.is_symlink():
                return False
            receipt_path = root / binding.receipt_relative_path
            object_path = root / "objects" / binding.canonical_vacancy_object_sha256
            if (
                receipt_path.is_symlink()
                or object_path.is_symlink()
                or not receipt_path.is_file()
                or not object_path.is_file()
            ):
                return False
            receipt_bytes = receipt_path.read_bytes()
            object_bytes = object_path.read_bytes()
            if (
                hashlib.sha256(receipt_bytes).hexdigest()
                != binding.receipt_file_sha256
                or hashlib.sha256(object_bytes).hexdigest()
                != binding.canonical_vacancy_object_sha256
            ):
                return False
            receipt = json.loads(receipt_bytes)
            semantic_body = dict(receipt)
            semantic = semantic_body.pop("semantic_receipt_sha256", None)
            if (
                receipt_bytes
                != json.dumps(
                    receipt,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                or semantic != binding.semantic_receipt_sha256
                or hashlib.sha256(
                    json.dumps(
                        semantic_body,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                != semantic
                or receipt.get("schema_version")
                != "market-aligner.public-research-materialization.v2"
                or receipt.get("dossier_sha256") != row["dossier_hash"]
            ):
                return False
            citations = document.get("citations")
            claims = document.get("claims")
            if (
                not isinstance(citations, list)
                or len(citations) != 1
                or citations[0].get("source_kind") != "canonical_vacancy"
                or citations[0].get("content_sha256")
                != binding.canonical_vacancy_object_sha256
                or not isinstance(claims, list)
                or not claims
            ):
                return False
            citation_id = citations[0].get("citation_id")
            for claim in claims:
                supports = claim.get("supports")
                if not isinstance(supports, list) or not supports:
                    return False
                for support in supports:
                    match = _BYTE_SELECTOR.fullmatch(str(support.get("selector", "")))
                    if match is None or support.get("citation_id") != citation_id:
                        return False
                    start, end = int(match.group(1)), int(match.group(2))
                    selected = object_bytes[start:end]
                    if (
                        end > len(object_bytes)
                        or hashlib.sha256(selected).hexdigest()
                        != support.get("excerpt_sha256")
                        or selected.decode("utf-8") != support.get("excerpt")
                        or " ".join(str(claim.get("claim", "")).split())
                        != " ".join(str(support.get("excerpt", "")).split())
                    ):
                        return False
            return True
        except (KeyError, TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError):
            return False

    def refresh_completed_research_if_needed(
        self,
        profile_id: str,
        job_key: str,
        *,
        collection_refresh_receipt_path: str | Path | None = None,
        collection_config_path: str | Path | None = None,
    ) -> bool:
        """Requeue invalid v2 evidence or admit one exact unchanged refresh."""

        validate_profile_id(profile_id)
        if (collection_refresh_receipt_path is None) != (collection_config_path is None):
            raise ValueError(
                "collection refresh admission requires both receipt and bound config"
        )
        if collection_refresh_receipt_path is not None:
            assert collection_config_path is not None
            return self._requeue_from_unchanged_collection_refresh(
                profile_id,
                job_key,
                receipt_path=Path(collection_refresh_receipt_path),
                config_path=Path(collection_config_path),
            )
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT q.status,q.job_key,a.title,a.company,a.url,
                          p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256,
                          d.dossier_json,d.dossier_hash,
                          e.dossier_hash AS evidence_dossier_hash,
                          e.source_content_sha256 AS evidence_source_content_sha256,
                          e.vacancy_snapshot_sha256 AS evidence_vacancy_snapshot_sha256,
                          e.promotion_receipt_sha256 AS evidence_promotion_receipt_sha256,
                          e.canonical_vacancy_object_sha256,
                          e.semantic_receipt_sha256,e.receipt_file_sha256,
                          e.archive_root_identity,e.archive_root_policy_sha256,
                          e.receipt_relative_path,
                          e.schema_version AS evidence_schema_version
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   LEFT JOIN employer_research_evidence e
                     ON e.profile_id=q.profile_id AND e.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (profile_id, job_key),
            ).fetchone()
            if row is None:
                raise KeyError((profile_id, job_key))
            if row["status"] != "completed" or self._has_current_v2_evidence(row):
                return False
            connection.execute(
                """UPDATE employer_research_queue SET status='queued',available_at=CURRENT_TIMESTAMP,
                     lease_owner=NULL,lease_until=NULL,last_error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                ("completed research lacks valid current v2 evidence", profile_id, job_key),
            )
            connection.execute(
                "DELETE FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            )
            connection.execute(
                """UPDATE assessments SET state='employer_research_queued',
                     updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (profile_id, job_key),
            )
            connection.execute(
                """INSERT OR IGNORE INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "employer_research_v2_refresh_queued",
                    "deterministic",
                    json.dumps(
                        {
                            "prior_dossier_hash": row["dossier_hash"],
                            "promotion_receipt_sha256": row[
                                "promotion_receipt_sha256"
                            ],
                            "reason": "missing_or_invalid_current_v2_evidence",
                        },
                        sort_keys=True,
                    ),
                    (
                        f"research-v2-refresh:{profile_id}:{job_key}:"
                        f"{row['dossier_hash']}:{row['promotion_receipt_sha256']}"
                    ),
                ),
            )
            return True

    def _has_current_v2_refresh_chain(
        self, row: sqlite3.Row, *, collector_content_sha256: str
    ) -> bool:
        """Verify that current v2 evidence terminates at the prior refresh event."""

        if row["status"] != "completed" or not self._has_current_v2_evidence(row):
            return False
        try:
            payload = json.loads(str(row["prior_refresh_payload_json"]))
            prior_event_id = row["prior_refresh_event_id"]
            event_key = (
                f"research-collection-refresh:{row['profile_id']}:{row['job_key']}:"
                f"{payload.get('collection_transition_sha256')}"
            )
            root = (self.data_home / row["archive_root_identity"]).resolve()
            object_bytes = (
                root / "objects" / row["canonical_vacancy_object_sha256"]
            ).read_bytes()
            envelope = json.loads(object_bytes)
            if (
                not isinstance(payload, dict)
                or not isinstance(envelope, dict)
                or hashlib.sha256(object_bytes).hexdigest()
                != row["canonical_vacancy_object_sha256"]
                or object_bytes
                != json.dumps(
                    envelope,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                or row["prior_refresh_event_type"]
                != "employer_research_collection_refresh_queued"
                or row["prior_refresh_actor_kind"] != "deterministic"
                or row["prior_refresh_idempotency_key"] != event_key
                or payload.get("refresh_bridge_sha256")
                != row["prior_refresh_bridge_sha256"]
                or research_refresh_bridge_sha256(
                    event_type=str(row["prior_refresh_event_type"]),
                    actor_kind=str(row["prior_refresh_actor_kind"]),
                    idempotency_key=str(row["prior_refresh_idempotency_key"]),
                    payload=payload,
                )
                != row["prior_refresh_bridge_sha256"]
                or payload.get("source_content_sha256") != row["source_content_sha256"]
                or payload.get("promotion_receipt_sha256")
                != row["promotion_receipt_sha256"]
                or not research_refresh_preserves_source_authority(
                    source_content_sha256=row["source_content_sha256"],
                    old_collector_content_sha256=payload.get(
                        "old_collector_content_sha256"
                    ),
                    old_canonical_content_sha256=payload.get(
                        "old_canonical_content_sha256"
                    ),
                )
                or payload.get("old_canonical_content_sha256")
                != collector_content_sha256
                or envelope.get("schema_version")
                != "market-aligner.canonical-collector-vacancy.v2"
                or envelope.get("authority_source_content_sha256")
                != row["source_content_sha256"]
                or envelope.get("canonical_current_content_sha256")
                != collector_content_sha256
                or envelope.get("collection_refresh_event_id") != prior_event_id
                or envelope.get("collection_refresh_context_sha256")
                != payload.get("collection_context_sha256")
                or envelope.get("collection_refresh_operation_id")
                != payload.get("collection_operation_id")
                or envelope.get("collection_refresh_receipt_file_sha256")
                != payload.get("collection_receipt_file_sha256")
                or envelope.get("collection_refresh_receipt_sha256")
                != payload.get("collection_receipt_sha256")
                or envelope.get("collection_refresh_id")
                != payload.get("collection_refresh_id")
                or envelope.get("collection_refresh_transition_sha256")
                != payload.get("collection_transition_sha256")
                or envelope.get("collection_refresh_raw_object_sha256")
                != payload.get("new_raw_object_sha256")
                or envelope.get("fetched_at") != payload.get("new_fetched_at")
                or envelope.get("job_key") != row["job_key"]
                or envelope.get("promotion_receipt_sha256")
                != row["promotion_receipt_sha256"]
            ):
                return False
            return True
        except (
            KeyError,
            TypeError,
            ValueError,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return False

    def _requeue_from_unchanged_collection_refresh(
        self,
        profile_id: str,
        job_key: str,
        *,
        receipt_path: Path,
        config_path: Path,
    ) -> bool:
        """Atomically bind a locked collector snapshot to the research requeue."""

        resolved_collector = JobDatabase.resolve_vacancy_refresh_collector(
            self.data_home, receipt_path, config_path
        )
        collector_database = resolved_collector.database
        expected_collector = resolved_collector.path
        supplied_collector = collector_database.path.absolute()
        if (
            collector_database.data_home != self.data_home.absolute()
            or supplied_collector != expected_collector
            or self.data_home not in supplied_collector.parents
        ):
            raise ValueError("collector database is outside the assessment data home")
        connection = self.connect()
        try:
            connection.execute("ATTACH DATABASE ? AS collector", (str(expected_collector),))
            attached = {
                str(row[1]): Path(str(row[2])).absolute()
                for row in connection.execute("PRAGMA database_list")
            }
            if attached.get("collector") != expected_collector:
                raise ValueError("attached collector database identity differs")
            # BEGIN IMMEDIATE reserves both the assessment and attached collector
            # databases.  No collector writer can change the row between exact
            # verification and the assessment-side commit.
            connection.execute("BEGIN IMMEDIATE")
            resolved_collector.verify_open_connection(
                connection, schema="collector"
            )
            verified = collector_database.verify_vacancy_refresh_receipt(
                receipt_path,
                job_key=job_key,
                connection=connection,
                schema="collector",
            )
            row = connection.execute(
                """SELECT q.status,q.profile_id,q.job_key,q.refresh_event_id
                          AS prior_refresh_event_id,q.refresh_bridge_sha256
                          AS prior_refresh_bridge_sha256,
                          a.state,a.title,a.company,a.url,
                          p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256,
                          d.dossier_json,d.dossier_hash,
                          pe.event_type AS prior_refresh_event_type,
                          pe.actor_kind AS prior_refresh_actor_kind,
                          pe.payload_json AS prior_refresh_payload_json,
                          pe.idempotency_key AS prior_refresh_idempotency_key,
                          e.dossier_hash AS evidence_dossier_hash,
                          e.source_content_sha256 AS evidence_source_content_sha256,
                          e.vacancy_snapshot_sha256
                          AS evidence_vacancy_snapshot_sha256,
                          e.promotion_receipt_sha256
                          AS evidence_promotion_receipt_sha256,
                          e.canonical_vacancy_object_sha256,
                          e.semantic_receipt_sha256,e.receipt_file_sha256,
                          e.archive_root_identity,e.archive_root_policy_sha256,
                          e.receipt_relative_path,
                          e.schema_version AS evidence_schema_version
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   LEFT JOIN employer_research_evidence e
                     ON e.profile_id=q.profile_id AND e.job_key=q.job_key
                   LEFT JOIN assessment_events pe
                     ON pe.id=q.refresh_event_id
                    AND pe.profile_id=q.profile_id AND pe.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (profile_id, job_key),
            ).fetchone()
            if row is None:
                raise KeyError((profile_id, job_key))
            if (
                verified.changed
                or verified.old_canonical_content_sha256
                != verified.new_content_sha256
            ):
                raise ValueError(
                    "changed vacancy content requires assessment promotion supersession"
                )
            promotion_source = row["source_content_sha256"]
            if promotion_source is None:
                raise ValueError("refresh lacks a current assessment promotion")
            event_key = (
                f"research-collection-refresh:{profile_id}:{job_key}:"
                f"{verified.transition_sha256}"
            )
            existing_event = connection.execute(
                """SELECT id,event_type,actor_kind,payload_json
                   FROM assessment_events WHERE idempotency_key=?""",
                (event_key,),
            ).fetchone()
            if (
                existing_event is None
                and promotion_source != verified.old_content_sha256
                and not self._has_current_v2_refresh_chain(
                    row, collector_content_sha256=verified.old_content_sha256
                )
            ):
                raise ValueError(
                    "refresh content lacks current assessment promotion ancestry"
                )
            payload = {
                "collection_context_sha256": verified.context_sha256,
                "collection_operation_id": verified.operation_id,
                "collection_receipt_file_sha256": verified.receipt_file_sha256,
                "collection_receipt_sha256": verified.receipt_sha256,
                "collection_refresh_id": verified.refresh_id,
                "collection_transition_sha256": verified.transition_sha256,
                "new_fetched_at": verified.new_fetched_at,
                "new_raw_object_sha256": verified.new_raw_object_sha256,
                "old_canonical_content_sha256": (
                    verified.old_canonical_content_sha256
                ),
                "old_collector_content_sha256": verified.old_content_sha256,
                "prior_dossier_hash": row["dossier_hash"],
                "promotion_receipt_sha256": row["promotion_receipt_sha256"],
                "source_content_sha256": promotion_source,
            }
            bridge_sha256 = research_refresh_bridge_sha256(
                event_type="employer_research_collection_refresh_queued",
                actor_kind="deterministic",
                idempotency_key=event_key,
                payload=payload,
            )
            payload["refresh_bridge_sha256"] = bridge_sha256
            if existing_event is not None:
                queue_event = connection.execute(
                    """SELECT refresh_event_id FROM employer_research_queue
                       WHERE profile_id=? AND job_key=?""",
                    (profile_id, job_key),
                ).fetchone()
                try:
                    existing_payload = json.loads(existing_event["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        "collection refresh replay event is invalid"
                    ) from exc
                prior_hash = (
                    existing_payload.get("prior_dossier_hash")
                    if isinstance(existing_payload, dict)
                    else None
                )
                replay_payload = dict(payload)
                replay_payload["prior_dossier_hash"] = prior_hash
                replay_payload["refresh_bridge_sha256"] = (
                    research_refresh_bridge_sha256(
                        event_type=(
                            "employer_research_collection_refresh_queued"
                        ),
                        actor_kind="deterministic",
                        idempotency_key=event_key,
                        payload=replay_payload,
                    )
                )
                if (
                    existing_event["event_type"]
                    != "employer_research_collection_refresh_queued"
                    or existing_event["actor_kind"] != "deterministic"
                    or not isinstance(prior_hash, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", prior_hash)
                    or existing_event["payload_json"]
                    != json.dumps(
                        replay_payload, sort_keys=True, separators=(",", ":")
                    )
                    or queue_event is None
                    or queue_event["refresh_event_id"] != existing_event["id"]
                ):
                    raise ValueError("collection refresh replay binding differs")
                connection.rollback()
                return False
            if row["status"] != "completed":
                raise ValueError(
                    "collection refresh can requeue only completed employer research"
                )

            cursor = connection.execute(
                """INSERT INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "employer_research_collection_refresh_queued",
                    "deterministic",
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    event_key,
                ),
            )
            refresh_event_id = int(cursor.lastrowid)
            updated = connection.execute(
                """UPDATE employer_research_queue SET status='queued',
                     available_at=CURRENT_TIMESTAMP,lease_owner=NULL,lease_until=NULL,
                     last_error=?,refresh_event_id=?,refresh_bridge_sha256=?,
                     updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=? AND status='completed'""",
                (
                    "canonical vacancy fetched_at changed under unchanged content",
                    refresh_event_id,
                    bridge_sha256,
                    profile_id,
                    job_key,
                ),
            )
            if updated.rowcount != 1:
                raise ValueError("research refresh queue transition raced")
            connection.execute(
                "DELETE FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            )
            connection.execute(
                """UPDATE assessments SET state='employer_research_queued',
                     updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (profile_id, job_key),
            )
            # A second call through the same canonical verifier occurs while the
            # collector reservation is still held and before assessment commit.
            revalidated = collector_database.verify_vacancy_refresh_receipt(
                receipt_path,
                job_key=job_key,
                connection=connection,
                schema="collector",
            )
            if revalidated != verified:
                raise ValueError("collector refresh changed during assessment admission")
            resolved_collector.verify_open_connection(
                connection, schema="collector"
            )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_research(
        self,
        dossier: ResearchDossier,
        worker_id: str,
        evidence: ResearchEvidenceBinding | None = None,
    ) -> str:
        dossier.validate()
        payload = json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        receipt_bytes: bytes | None = None
        if dossier.schema_version == "market-aligner.employer-dossier.v2":
            if evidence is None:
                raise ValueError("v2 research completion requires archive evidence")
            evidence.validate()
            if (
                evidence.dossier_sha256 != digest
                or evidence.source_content_sha256 != dossier.source_content_sha256
                or evidence.vacancy_snapshot_sha256 != dossier.vacancy_snapshot_sha256
                or evidence.promotion_receipt_sha256 != dossier.promotion_receipt_sha256
                or evidence.canonical_vacancy_object_sha256
                != dossier.canonical_vacancy_object_sha256
            ):
                raise ValueError("research archive evidence differs from dossier bindings")
            if (
                evidence.archive_root_policy_sha256
                != RESEARCH_ARCHIVE_ROOT_POLICY_SHA256
            ):
                raise ValueError("research archive root policy differs")
            root = (self.data_home / evidence.archive_root_identity).resolve()
            if self.data_home not in root.parents:
                raise ValueError("research archive root escapes protected data home")
            receipt_path = root / evidence.receipt_relative_path
            if root.is_symlink() or receipt_path.is_symlink() or not receipt_path.is_file():
                raise ValueError("research archive receipt path is unsafe")
            receipt_bytes = receipt_path.read_bytes()
            if hashlib.sha256(receipt_bytes).hexdigest() != evidence.receipt_file_sha256:
                raise ValueError("research archive exact receipt file differs")
            try:
                receipt = json.loads(receipt_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("research archive receipt is invalid JSON") from exc
            body = dict(receipt) if isinstance(receipt, dict) else {}
            semantic = body.pop("semantic_receipt_sha256", None)
            semantic_digest = hashlib.sha256(
                json.dumps(
                    body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            if (
                receipt_bytes
                != json.dumps(
                    receipt,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                or semantic != evidence.semantic_receipt_sha256
                or semantic_digest != semantic
                or receipt.get("schema_version")
                != "market-aligner.public-research-materialization.v2"
                or receipt.get("dossier_sha256") != digest
                or receipt.get("source_content_sha256")
                != dossier.source_content_sha256
                or receipt.get("vacancy_snapshot_sha256")
                != dossier.vacancy_snapshot_sha256
                or receipt.get("promotion_receipt_sha256")
                != dossier.promotion_receipt_sha256
                or receipt.get("canonical_vacancy_object_sha256")
                != dossier.canonical_vacancy_object_sha256
            ):
                raise ValueError("research archive semantic receipt differs")
        elif evidence is not None:
            raise ValueError("legacy dossier cannot claim v2 archive evidence")
        with self.transaction() as connection:
            lease = connection.execute(
                """SELECT q.lease_owner,q.status,q.refresh_event_id,
                          q.refresh_bridge_sha256,
                          e.event_type,e.actor_kind,e.payload_json,e.idempotency_key,
                          d.dossier_hash AS current_dossier_hash,
                          d.dossier_json AS current_dossier_json,
                          p.source_content_sha256,
                          p.receipt_sha256 AS current_promotion_receipt_sha256
                   FROM employer_research_queue q
                   LEFT JOIN assessment_events e
                     ON e.id=q.refresh_event_id
                    AND e.profile_id=q.profile_id AND e.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (dossier.profile_id, dossier.job_key),
            ).fetchone()
            if lease is None or lease["status"] != "leased" or lease["lease_owner"] != worker_id:
                raise RuntimeError("research completion requires the active lease")
            if lease["refresh_event_id"] is not None:
                try:
                    refresh_payload = json.loads(str(lease["payload_json"]))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        "research completion refresh event is invalid"
                    ) from exc
                if (
                    lease["event_type"]
                    != "employer_research_collection_refresh_queued"
                    or lease["actor_kind"] != "deterministic"
                    or not isinstance(refresh_payload, dict)
                    or lease["idempotency_key"]
                    != (
                        f"research-collection-refresh:{dossier.profile_id}:"
                        f"{dossier.job_key}:"
                        f"{refresh_payload.get('collection_transition_sha256')}"
                    )
                    or refresh_payload.get("prior_dossier_hash")
                    != lease["current_dossier_hash"]
                    or not isinstance(lease["current_dossier_json"], str)
                    or hashlib.sha256(
                        lease["current_dossier_json"].encode("utf-8")
                    ).hexdigest()
                    != lease["current_dossier_hash"]
                    or refresh_payload.get("source_content_sha256")
                    != dossier.source_content_sha256
                    or not research_refresh_preserves_source_authority(
                        source_content_sha256=lease["source_content_sha256"],
                        old_collector_content_sha256=refresh_payload.get(
                            "old_collector_content_sha256"
                        ),
                        old_canonical_content_sha256=refresh_payload.get(
                            "old_canonical_content_sha256"
                        ),
                    )
                    or refresh_payload.get("promotion_receipt_sha256")
                    != dossier.promotion_receipt_sha256
                    or lease["current_promotion_receipt_sha256"]
                    != dossier.promotion_receipt_sha256
                    or refresh_payload.get("refresh_bridge_sha256")
                    != lease["refresh_bridge_sha256"]
                    or research_refresh_bridge_sha256(
                        event_type=str(lease["event_type"]),
                        actor_kind=str(lease["actor_kind"]),
                        idempotency_key=str(lease["idempotency_key"]),
                        payload=refresh_payload,
                    )
                    != lease["refresh_bridge_sha256"]
                ):
                    raise ValueError(
                        "research completion refresh authority differs"
                    )
            connection.execute(
                """INSERT INTO employer_dossiers(profile_id,job_key,dossier_json,dossier_hash,worker_id)
                   VALUES(?,?,?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                   dossier_json=excluded.dossier_json,dossier_hash=excluded.dossier_hash,
                   worker_id=excluded.worker_id,created_at=CURRENT_TIMESTAMP""",
                (dossier.profile_id, dossier.job_key, payload, digest, worker_id),
            )
            if evidence is not None:
                connection.execute(
                    """INSERT INTO employer_research_evidence(
                         profile_id,job_key,dossier_hash,source_content_sha256,
                         vacancy_snapshot_sha256,promotion_receipt_sha256,
                         canonical_vacancy_object_sha256,
                         semantic_receipt_sha256,receipt_file_sha256,
                         archive_root_identity,archive_root_policy_sha256,
                         receipt_relative_path,schema_version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(profile_id,job_key)
                       DO UPDATE SET dossier_hash=excluded.dossier_hash,
                         source_content_sha256=excluded.source_content_sha256,
                         vacancy_snapshot_sha256=excluded.vacancy_snapshot_sha256,
                         promotion_receipt_sha256=excluded.promotion_receipt_sha256,
                         canonical_vacancy_object_sha256=excluded.canonical_vacancy_object_sha256,
                         semantic_receipt_sha256=excluded.semantic_receipt_sha256,
                         receipt_file_sha256=excluded.receipt_file_sha256,
                         archive_root_identity=excluded.archive_root_identity,
                         archive_root_policy_sha256=excluded.archive_root_policy_sha256,
                         receipt_relative_path=excluded.receipt_relative_path,
                         schema_version=excluded.schema_version,
                         created_at=CURRENT_TIMESTAMP""",
                    (
                        dossier.profile_id,
                        dossier.job_key,
                        digest,
                        evidence.source_content_sha256,
                        evidence.vacancy_snapshot_sha256,
                        evidence.promotion_receipt_sha256,
                        evidence.canonical_vacancy_object_sha256,
                        evidence.semantic_receipt_sha256,
                        evidence.receipt_file_sha256,
                        evidence.archive_root_identity,
                        evidence.archive_root_policy_sha256,
                        evidence.receipt_relative_path,
                        evidence.schema_version,
                    ),
                )
            else:
                connection.execute(
                    "DELETE FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                    (dossier.profile_id, dossier.job_key),
                )
            connection.execute(
                """UPDATE employer_research_queue SET status='completed',lease_owner=NULL,
                     lease_until=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (dossier.profile_id, dossier.job_key),
            )
            connection.execute(
                """UPDATE assessments SET state='employer_researched',updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (dossier.profile_id, dossier.job_key),
            )
        return digest

    def research_evidence(self, profile_id: str, job_key: str) -> sqlite3.Row:
        """Return a v2 dossier and its reconciled archive binding only."""

        with self.connection() as connection:
            row = connection.execute(
                """SELECT d.dossier_json,d.dossier_hash,e.*
                   FROM employer_dossiers d JOIN employer_research_evidence e
                     ON e.profile_id=d.profile_id AND e.job_key=d.job_key
                   WHERE d.profile_id=? AND d.job_key=?
                     AND d.dossier_hash=e.dossier_hash""",
                (profile_id, job_key),
            ).fetchone()
        if row is None:
            raise KeyError((profile_id, job_key))
        return row

    def fail_research(
        self,
        profile_id: str,
        job_key: str,
        worker_id: str,
        error: str,
        *,
        retry_seconds: int = 300,
    ) -> None:
        available_at = datetime.now(timezone.utc) + timedelta(seconds=max(1, retry_seconds))
        with self.transaction() as connection:
            lease = connection.execute(
                """SELECT lease_owner,status FROM employer_research_queue
                   WHERE profile_id=? AND job_key=?""",
                (profile_id, job_key),
            ).fetchone()
            if lease is None or lease["status"] != "leased" or lease["lease_owner"] != worker_id:
                raise RuntimeError("research failure requires the active lease")
            connection.execute(
                """UPDATE employer_research_queue SET status='queued',lease_owner=NULL,
                     lease_until=NULL,last_error=?,available_at=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (error[:2000], available_at.isoformat(), profile_id, job_key),
            )
