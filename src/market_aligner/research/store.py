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
from market_aligner.state.vacancies import ProjectionConflict

from .models import ResearchDossier, ResearchTask


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
  queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
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

CREATE TRIGGER IF NOT EXISTS research_requires_opportunity_pass
BEFORE INSERT ON employer_research_queue
WHEN COALESCE((SELECT opportunity_decision FROM assessments
               WHERE profile_id=NEW.profile_id AND job_key=NEW.job_key),'') != 'pass'
BEGIN
  SELECT RAISE(ABORT, 'employer research requires a passed opportunity gate');
END;
"""


class AssessmentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(SCHEMA)

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
        payload, digest = canonical_score_payload(result)
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
                       priority=excluded.priority,updated_at=CURRENT_TIMESTAMP""",
                    (profile_id, job_key, priority),
                )
            else:
                connection.execute(
                    """DELETE FROM employer_research_queue
                       WHERE profile_id=? AND job_key=? AND status='queued'""",
                    (profile_id, job_key),
                )

    def enqueue_research(self, profile_id: str, job_key: str, priority: int) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO employer_research_queue(profile_id,job_key,priority) VALUES(?,?,?)",
                (profile_id, job_key, priority),
            )

    def claim_research(self, worker_id: str, lease_seconds: int = 900) -> ResearchTask | None:
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=max(1, lease_seconds))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT q.profile_id,q.job_key,a.title,a.company,a.url,a.opportunity,
                          q.priority,q.attempts
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   WHERE (q.status='queued' AND q.available_at<=CURRENT_TIMESTAMP)
                      OR (q.status='leased' AND q.lease_until<CURRENT_TIMESTAMP)
                   ORDER BY q.priority DESC,a.opportunity DESC,q.queued_at LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """UPDATE employer_research_queue SET status='leased',attempts=attempts+1,
                     lease_owner=?,lease_until=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (worker_id, lease_until.isoformat(), row["profile_id"], row["job_key"]),
            )
            return ResearchTask(**dict(row))

    def complete_research(self, dossier: ResearchDossier, worker_id: str) -> str:
        dossier.validate()
        payload = json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self.transaction() as connection:
            lease = connection.execute(
                """SELECT lease_owner,status FROM employer_research_queue
                   WHERE profile_id=? AND job_key=?""",
                (dossier.profile_id, dossier.job_key),
            ).fetchone()
            if lease is None or lease["status"] != "leased" or lease["lease_owner"] != worker_id:
                raise RuntimeError("research completion requires the active lease")
            connection.execute(
                """INSERT INTO employer_dossiers(profile_id,job_key,dossier_json,dossier_hash,worker_id)
                   VALUES(?,?,?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                   dossier_json=excluded.dossier_json,dossier_hash=excluded.dossier_hash,
                   worker_id=excluded.worker_id,created_at=CURRENT_TIMESTAMP""",
                (dossier.profile_id, dossier.job_key, payload, digest, worker_id),
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


# ==========================================================================
# FIT-001 Part-3C C1: caller-owned read-plan/CAS helpers.
#
# Every helper below operates strictly on an existing caller-owned
# sqlite3.Connection. They never connect, begin or end transactions,
# change journal settings, run migrations, or issue UPDATE / INSERT OR
# IGNORE / UPSERT statements; the only DML is an explicit single-row
# INSERT driven by a frozen plan, always followed by an exact reread and
# a frozen durable projection result. Reads use explicit column lists so
# caller row_factory choices are irrelevant and never mutated.
# ==========================================================================

_PROCESSING_SCORE_ACCEPTED = "processing_score_accepted"
_ELIGIBILITY_DECIDED = "eligibility_decided"
_EVENT_TYPES = frozenset({_PROCESSING_SCORE_ACCEPTED, _ELIGIBILITY_DECIDED})
_MAX_IDEMPOTENCY_KEY_BYTES = 512

_RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


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


_SCORE_PROJECTION_COLUMNS = (
    "profile_id", "job_key", "url", "title", "company",
    "opportunity", "fit", "final_score", "fit_status",
    "extraction_confidence", "score_payload_json", "score_payload_hash",
    "state", "created_at", "updated_at",
)

_SCORE_ADVANCED_COLUMNS = (
    "opportunity_decision", "opportunity_reason", "policy_hash",
)
_SCORE_ROW_COLUMNS = _SCORE_PROJECTION_COLUMNS + _SCORE_ADVANCED_COLUMNS


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


_EVENT_PROJECTION_COLUMNS = (
    "id", "profile_id", "job_key", "event_type", "actor_kind",
    "payload_json", "idempotency_key", "created_at",
)


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
