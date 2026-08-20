"""Persistent, append-preserving storage for the collection pipeline."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from market_aligner.domain.contracts import (
    JobUrl,
    RawPosting,
    from_dict,
    read_jsonl,
    to_dict,
    write_jsonl,
)
from market_aligner.state.importers import iter_raw_cache_roots


LEGACY_PROCESSING_CONFIG_SHA256 = "0" * 64


class VacancyRefreshConflict(RuntimeError):
    """The exact fetched vacancy changed before a guarded refresh committed."""


def raw_posting_content_sha256(row: RawPosting) -> str:
    """Return the existing collector content identity for a raw posting."""

    raw_json = json.dumps(row.raw_json, ensure_ascii=False) if row.raw_json is not None else None
    material = (row.raw_text or "") + (raw_json or "")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def raw_posting_bytes(row: RawPosting) -> bytes:
    """Serialize the exact collector C2 response stored in raw-cache objects."""

    return (json.dumps(to_dict(row), ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def raw_posting_from_bytes(value: bytes) -> RawPosting:
    """Validate and decode one exact collector C2 response object."""

    try:
        text = value.decode("utf-8")
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) != 1:
            raise ValueError("raw response object must contain exactly one JSON record")
        payload = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("raw response object is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("raw response object must be a JSON object")
    row = from_dict(RawPosting, payload)
    if raw_posting_bytes(row) != value:
        raise ValueError("raw response object is not in canonical collector encoding")
    return row


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=30000;
CREATE TABLE IF NOT EXISTS postings (
  key TEXT PRIMARY KEY, board TEXT NOT NULL, job_id TEXT NOT NULL, url TEXT NOT NULL,
  posted_at TEXT, first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, fetched_at TEXT,
  raw_text TEXT, raw_json TEXT, content_hash TEXT, fetch_status TEXT NOT NULL DEFAULT 'discovered',
  fetch_error TEXT
);
CREATE INDEX IF NOT EXISTS postings_board_status ON postings(board, fetch_status);
CREATE TABLE IF NOT EXISTS normalised_jobs (
  key TEXT PRIMARY KEY, normalized_json TEXT NOT NULL, normalized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scores (
  key TEXT PRIMARY KEY, score_json TEXT NOT NULL, scored_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS source_state (
  board TEXT PRIMARY KEY, last_polled_at TEXT, last_error TEXT
);
CREATE TABLE IF NOT EXISTS collection_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT, discovered INTEGER NOT NULL DEFAULT 0, fetched INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vacancy_refreshes (
  refresh_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  context_sha256 TEXT NOT NULL,
  job_key TEXT NOT NULL,
  expected_content_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('intent','fetched','object_ready','committed')),
  started_at TEXT NOT NULL,
  old_content_sha256 TEXT NOT NULL,
  old_fetched_at TEXT NOT NULL,
  old_raw_bytes BLOB NOT NULL,
  old_object_sha256 TEXT NOT NULL,
  new_content_sha256 TEXT,
  new_fetched_at TEXT,
  new_raw_bytes BLOB,
  new_object_sha256 TEXT,
  receipt_basis_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS processing_jobs (
  profile_id TEXT NOT NULL,
  track TEXT NOT NULL,
  job_key TEXT NOT NULL,
  authority_sha256 TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  processing_config_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('leased','completed','failed')),
  lease_owner TEXT,
  lease_until REAL,
  result_json TEXT,
  error TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(
    profile_id,track,job_key,authority_sha256,source_content_sha256,
    processing_config_sha256
  ),
  FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE CASCADE
);
"""


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class JobDatabase:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn, conn:
            conn.executescript(SCHEMA)
            self._migrate_processing_identity(conn)

    @staticmethod
    def _migrate_processing_identity(conn: sqlite3.Connection) -> None:
        """Bind legacy processing rows to an explicit, non-current config identity.

        SQLite cannot extend a primary key in place.  Existing v1 rows are copied
        intact under a reserved digest.  They remain available as semantic cache,
        but no current-config report or resume query can mistake them for a fresh
        decision.
        """

        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(processing_jobs)")
        }
        if "processing_config_sha256" in columns:
            conn.execute(
                """CREATE INDEX IF NOT EXISTS processing_jobs_resume ON processing_jobs(
                     profile_id,track,authority_sha256,processing_config_sha256,
                     status,lease_until
                   )"""
            )
            return
        conn.execute("DROP INDEX IF EXISTS processing_jobs_resume")
        conn.execute("ALTER TABLE processing_jobs RENAME TO processing_jobs_v1")
        conn.execute(
            """CREATE TABLE processing_jobs (
                 profile_id TEXT NOT NULL,
                 track TEXT NOT NULL,
                 job_key TEXT NOT NULL,
                 authority_sha256 TEXT NOT NULL,
                 source_content_sha256 TEXT NOT NULL,
                 processing_config_sha256 TEXT NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('leased','completed','failed')),
                 lease_owner TEXT,
                 lease_until REAL,
                 result_json TEXT,
                 error TEXT,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY(
                   profile_id,track,job_key,authority_sha256,source_content_sha256,
                   processing_config_sha256
                 ),
                 FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE CASCADE
               )"""
        )
        conn.execute(
            """INSERT INTO processing_jobs(
                 profile_id,track,job_key,authority_sha256,source_content_sha256,
                 processing_config_sha256,status,lease_owner,lease_until,result_json,
                 error,updated_at
               )
               SELECT profile_id,track,job_key,authority_sha256,source_content_sha256,
                      ?,status,lease_owner,lease_until,result_json,error,updated_at
               FROM processing_jobs_v1""",
            (LEGACY_PROCESSING_CONFIG_SHA256,),
        )
        conn.execute("DROP TABLE processing_jobs_v1")
        conn.execute(
            """CREATE INDEX processing_jobs_resume ON processing_jobs(
                 profile_id,track,authority_sha256,processing_config_sha256,
                 status,lease_until
               )"""
        )

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def upsert_discovered(self, row: JobUrl) -> bool:
        with closing(self.connect()) as conn, conn:
            existed = conn.execute("SELECT 1 FROM postings WHERE key=?", (row.key,)).fetchone()
            conn.execute(
                """INSERT INTO postings(key,board,job_id,url,posted_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET url=excluded.url,
                     posted_at=COALESCE(excluded.posted_at,postings.posted_at),
                     last_seen_at=CURRENT_TIMESTAMP""",
                (row.key, row.board, row.job_id, row.url, row.posted_at),
            )
        return existed is None

    def has_raw(self, key: str) -> bool:
        with closing(self.connect()) as conn, conn:
            return conn.execute(
                "SELECT 1 FROM postings WHERE key=? AND fetch_status='fetched'", (key,)
            ).fetchone() is not None

    def store_raw(self, row: RawPosting) -> None:
        raw_json = json.dumps(row.raw_json, ensure_ascii=False) if row.raw_json is not None else None
        digest = raw_posting_content_sha256(row)
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """UPDATE postings SET fetched_at=?,raw_text=?,raw_json=?,content_hash=?,
                   fetch_status='fetched',fetch_error=NULL WHERE key=?""",
                (row.fetched_at, row.raw_text, raw_json, digest, row.key),
            )

    def fetched_posting(self, key: str) -> tuple[JobUrl, str, str]:
        """Load one existing fetched row and its guarded refresh identity."""

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT board,job_id,url,posted_at,content_hash,fetched_at,fetch_status
                   FROM postings WHERE key=?""",
                (key,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown vacancy key: {key}")
        if row[6] != "fetched" or not row[4] or not row[5]:
            raise ValueError(f"vacancy is not an existing fetched row: {key}")
        job = JobUrl(board=str(row[0]), job_id=str(row[1]), url=str(row[2]), posted_at=row[3])
        if job.key != key:
            raise ValueError(f"stored vacancy identity does not match key: {key}")
        return job, str(row[4]), str(row[5])

    def refresh_transition(
        self,
        operation_id: str,
        *,
        context_sha256: str,
    ) -> dict[str, object] | None:
        """Load one exact refresh journal, rejecting operation-ID substitution."""

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT refresh_id,operation_id,context_sha256,job_key,
                          expected_content_sha256,status,started_at,
                          old_content_sha256,old_fetched_at,old_raw_bytes,
                          old_object_sha256,new_content_sha256,new_fetched_at,
                          new_raw_bytes,new_object_sha256,receipt_basis_json
                   FROM vacancy_refreshes WHERE operation_id=?""",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        if row[2] != context_sha256:
            raise ValueError("refresh operation ID is already bound to another context")
        return {
            "refresh_id": str(row[0]),
            "operation_id": str(row[1]),
            "context_sha256": str(row[2]),
            "job_key": str(row[3]),
            "expected_content_sha256": str(row[4]),
            "status": str(row[5]),
            "started_at": str(row[6]),
            "old_content_sha256": str(row[7]),
            "old_fetched_at": str(row[8]),
            "old_raw_bytes": bytes(row[9]),
            "old_object_sha256": str(row[10]),
            "new_content_sha256": None if row[11] is None else str(row[11]),
            "new_fetched_at": None if row[12] is None else str(row[12]),
            "new_raw_bytes": None if row[13] is None else bytes(row[13]),
            "new_object_sha256": None if row[14] is None else str(row[14]),
            "receipt_basis": (
                None if row[15] is None else json.loads(str(row[15]))
            ),
        }

    def begin_vacancy_refresh(
        self,
        *,
        refresh_id: str,
        operation_id: str,
        context_sha256: str,
        job_key: str,
        expected_content_sha256: str,
        started_at: str,
        old_raw_bytes: bytes,
    ) -> dict[str, object]:
        """Persist an exact old-response intent before any official refetch."""

        for label, value in (
            ("refresh", refresh_id),
            ("context", context_sha256),
            ("expected content", expected_content_sha256),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{label} identity must be lowercase SHA-256")
        old_raw = raw_posting_from_bytes(old_raw_bytes)
        if old_raw.key != job_key:
            raise ValueError("old raw-cache response differs from refresh vacancy")
        old_object_sha256 = hashlib.sha256(old_raw_bytes).hexdigest()
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT context_sha256 FROM vacancy_refreshes WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                conn.rollback()
                if existing[0] != context_sha256:
                    raise ValueError("refresh operation ID is already bound to another context")
                loaded = self.refresh_transition(
                    operation_id, context_sha256=context_sha256
                )
                assert loaded is not None
                return loaded
            current = conn.execute(
                """SELECT content_hash,fetched_at,fetch_status
                   FROM postings WHERE key=?""",
                (job_key,),
            ).fetchone()
            if current is None:
                conn.rollback()
                raise KeyError(f"unknown vacancy key: {job_key}")
            if current[2] != "fetched" or current[0] != expected_content_sha256:
                conn.rollback()
                raise VacancyRefreshConflict(
                    f"vacancy differs from refresh intent: {job_key}"
                )
            if raw_posting_content_sha256(old_raw) != expected_content_sha256:
                conn.rollback()
                raise ValueError("old raw-cache response differs from SQLite content identity")
            conn.execute(
                """INSERT INTO vacancy_refreshes(
                     refresh_id,operation_id,context_sha256,job_key,
                     expected_content_sha256,status,started_at,
                     old_content_sha256,old_fetched_at,old_raw_bytes,
                     old_object_sha256
                   ) VALUES(?,?,?,?,?,'intent',?,?,?,?,?)""",
                (
                    refresh_id,
                    operation_id,
                    context_sha256,
                    job_key,
                    expected_content_sha256,
                    started_at,
                    expected_content_sha256,
                    str(current[1]),
                    old_raw_bytes,
                    old_object_sha256,
                ),
            )
            conn.commit()
        loaded = self.refresh_transition(operation_id, context_sha256=context_sha256)
        assert loaded is not None
        return loaded

    def record_vacancy_refresh_fetch(
        self,
        refresh_id: str,
        *,
        new_raw_bytes: bytes,
    ) -> None:
        """Journal fetched bytes before any content-object or posting update."""

        new_raw = raw_posting_from_bytes(new_raw_bytes)
        new_content_sha256 = raw_posting_content_sha256(new_raw)
        new_object_sha256 = hashlib.sha256(new_raw_bytes).hexdigest()
        with closing(self.connect()) as conn, conn:
            current = conn.execute(
                """SELECT job_key,status,new_raw_bytes,new_object_sha256
                   FROM vacancy_refreshes WHERE refresh_id=?""",
                (refresh_id,),
            ).fetchone()
            if current is None:
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            if str(current[0]) != new_raw.key:
                raise ValueError("fetched response differs from refresh vacancy")
            if current[1] != "intent":
                if current[2] != new_raw_bytes or current[3] != new_object_sha256:
                    raise VacancyRefreshConflict("refresh fetch bytes were substituted")
                return
            conn.execute(
                """UPDATE vacancy_refreshes SET status='fetched',
                     new_content_sha256=?,new_fetched_at=?,new_raw_bytes=?,
                     new_object_sha256=?,updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='intent'""",
                (
                    new_content_sha256,
                    new_raw.fetched_at,
                    new_raw_bytes,
                    new_object_sha256,
                    refresh_id,
                ),
            )

    def mark_vacancy_refresh_object_ready(
        self,
        refresh_id: str,
        *,
        object_sha256: str,
    ) -> None:
        """Record that the journalled new response has a durable CAS object."""

        with closing(self.connect()) as conn, conn:
            row = conn.execute(
                "SELECT status,new_object_sha256 FROM vacancy_refreshes WHERE refresh_id=?",
                (refresh_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            if row[1] != object_sha256:
                raise VacancyRefreshConflict("refresh object identity was substituted")
            if row[0] in ("object_ready", "committed"):
                return
            if row[0] != "fetched":
                raise VacancyRefreshConflict("refresh object cannot precede fetched bytes")
            conn.execute(
                """UPDATE vacancy_refreshes SET status='object_ready',
                     updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='fetched'""",
                (refresh_id,),
            )

    def seal_vacancy_refresh(
        self,
        refresh_id: str,
        *,
        receipt_basis: Mapping[str, object],
    ) -> dict[str, object]:
        """CAS the posting and seal its replayable receipt basis atomically."""

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT job_key,expected_content_sha256,status,old_content_sha256,
                          old_fetched_at,old_object_sha256,new_content_sha256,
                          new_fetched_at,new_raw_bytes,new_object_sha256,receipt_basis_json
                   FROM vacancy_refreshes WHERE refresh_id=?""",
                (refresh_id,),
            ).fetchone()
            if row is None:
                conn.rollback()
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            if row[2] == "committed":
                conn.rollback()
                return json.loads(str(row[10]))
            if row[2] != "object_ready" or row[8] is None:
                conn.rollback()
                raise VacancyRefreshConflict("refresh object is not ready for CAS")
            new_raw_bytes = bytes(row[8])
            new_raw = raw_posting_from_bytes(new_raw_bytes)
            current = conn.execute(
                "SELECT content_hash,fetch_status FROM postings WHERE key=?",
                (row[0],),
            ).fetchone()
            if current is None or current[1] != "fetched" or current[0] != row[1]:
                conn.rollback()
                raise VacancyRefreshConflict(
                    f"vacancy changed before refresh commit: {row[0]}"
                )
            raw_json = (
                json.dumps(new_raw.raw_json, ensure_ascii=False)
                if new_raw.raw_json is not None
                else None
            )
            cursor = conn.execute(
                """UPDATE postings SET url=?,fetched_at=?,raw_text=?,raw_json=?,
                     content_hash=?,fetch_status='fetched',fetch_error=NULL
                   WHERE key=? AND fetch_status='fetched' AND content_hash=?""",
                (
                    new_raw.url,
                    new_raw.fetched_at,
                    new_raw.raw_text,
                    raw_json,
                    row[6],
                    row[0],
                    row[1],
                ),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                raise VacancyRefreshConflict(
                    f"vacancy changed before refresh commit: {row[0]}"
                )
            state = self._collection_state_from_connection(conn)
            basis = {
                **dict(receipt_basis),
                "changed": row[6] != row[3],
                "new_content_sha256": str(row[6]),
                "new_fetched_at": str(row[7]),
                "new_raw_object_sha256": str(row[9]),
                "old_content_sha256": str(row[3]),
                "old_fetched_at": str(row[4]),
                "old_raw_object_sha256": str(row[5]),
                "state_sha256": _canonical_hash(state),
            }
            basis["transition_sha256"] = _canonical_hash(basis)
            encoded = json.dumps(
                basis,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            conn.execute(
                """UPDATE vacancy_refreshes SET status='committed',
                     receipt_basis_json=?,updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='object_ready'""",
                (encoded, refresh_id),
            )
            conn.commit()
        return basis

    def record_error(self, key: str, message: str) -> None:
        with closing(self.connect()) as conn, conn:
            conn.execute("UPDATE postings SET fetch_status='error',fetch_error=? WHERE key=?",
                         (message[:2000], key))

    def mark_source(self, board: str, error: str | None = None) -> None:
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """INSERT INTO source_state(board,last_polled_at,last_error)
                   VALUES(?,CURRENT_TIMESTAMP,?) ON CONFLICT(board) DO UPDATE SET
                   last_polled_at=CURRENT_TIMESTAMP,last_error=excluded.last_error""",
                (board, error),
            )

    def source_due(self, board: str, minimum_minutes: float) -> bool:
        with closing(self.connect()) as conn, conn:
            row = conn.execute("SELECT last_polled_at FROM source_state WHERE board=?", (board,)).fetchone()
        if not row or not row[0]:
            return True
        last = datetime.fromisoformat(str(row[0])).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last).total_seconds() >= minimum_minutes * 60

    def boards_with_pending_discoveries(self, boards: Iterable[str]) -> set[str]:
        """Boards whose discovered URLs still need their complete detail page.

        This makes a killed/interrupted cycle resumable immediately instead of
        stranding URLs until the source's normal polling interval elapses.
        """
        selected = [str(board) for board in boards]
        if not selected:
            return set()
        placeholders = ",".join("?" for _ in selected)
        with closing(self.connect()) as conn, conn:
            rows = conn.execute(
                f"SELECT DISTINCT board FROM postings WHERE fetch_status!='fetched' "
                f"AND board IN ({placeholders})",
                selected,
            ).fetchall()
        return {str(row[0]) for row in rows}

    def export_urls(self, path: str | Path) -> int:
        with closing(self.connect()) as conn, conn:
            rows = [JobUrl(board=r[0], job_id=r[1], url=r[2], posted_at=r[3]) for r in
                    conn.execute("SELECT board,job_id,url,posted_at FROM postings ORDER BY first_seen_at,key")]
        return write_jsonl(path, rows)

    def import_existing(self, urls_path: str | Path, raw_cache: str | Path) -> tuple[int, int]:
        return self.import_existing_roots(urls_path, [raw_cache])

    def import_existing_roots(
        self,
        urls_path: str | Path,
        raw_cache_roots: Iterable[str | Path],
    ) -> tuple[int, int]:
        urls = Path(urls_path)
        added = fetched = 0
        if urls.exists():
            for row in read_jsonl(urls, JobUrl):
                added += int(self.upsert_discovered(row))
        for row in iter_raw_cache_roots(raw_cache_roots):
            if not self.has_raw(row.key):
                if self.upsert_discovered(JobUrl(row.board, row.job_id, row.url)):
                    added += 1
                self.store_raw(row)
                fetched += 1
        return added, fetched

    def sync_jsonl(self, path: str | Path, table: str, json_column: str) -> int:
        if table not in {"normalised_jobs", "scores"}:
            raise ValueError(table)
        source = Path(path)
        if not source.exists():
            return 0
        count = 0
        with closing(self.connect()) as conn, conn:
            for row in read_jsonl(source):
                key = f"{row.get('board')}:{row.get('job_id')}"
                conn.execute(
                    f"INSERT INTO {table}(key,{json_column}) VALUES(?,?) "
                    f"ON CONFLICT(key) DO UPDATE SET {json_column}=excluded.{json_column}",
                    (key, json.dumps(row, ensure_ascii=False)),
                )
                count += 1
        return count

    def stats(self) -> dict[str, int]:
        with closing(self.connect()) as conn, conn:
            total = conn.execute("SELECT COUNT(*) FROM postings").fetchone()[0]
            fetched = conn.execute("SELECT COUNT(*) FROM postings WHERE fetch_status='fetched'").fetchone()[0]
            normalized = conn.execute("SELECT COUNT(*) FROM normalised_jobs").fetchone()[0]
            scored = conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
        return {"postings": total, "fetched": fetched, "normalized": normalized, "scored": scored}

    def collection_state(self) -> dict[str, object]:
        """Return a deterministic projection of resumable collection state."""

        with closing(self.connect()) as conn:
            return self._collection_state_from_connection(conn)

    @staticmethod
    def _collection_state_from_connection(
        conn: sqlite3.Connection,
    ) -> dict[str, object]:
        postings = [
            {
                "board": row[0],
                "job_id": row[1],
                "url": row[2],
                "content_hash": row[3],
                "fetch_status": row[4],
                "fetch_error": row[5],
            }
            for row in conn.execute(
                """SELECT board,job_id,url,content_hash,fetch_status,fetch_error
                   FROM postings ORDER BY board,job_id"""
            )
        ]
        sources = [
            {
                "board": row[0],
                "last_polled_at": row[1],
                "last_error": row[2],
            }
            for row in conn.execute(
                """SELECT board,last_polled_at,last_error
                   FROM source_state ORDER BY board"""
            )
        ]
        return {
            "postings": postings,
            "schema_version": "market-aligner.collection-state.v1",
            "sources": sources,
        }

    def promote_fetched_from(
        self,
        source_path: str | Path,
        *,
        config_sha256: str,
        job_key: str | None = None,
    ) -> dict[str, object]:
        """Atomically copy a verified collector snapshot into canonical processing state."""

        source = Path(source_path).expanduser().resolve()
        target = self.path.expanduser().resolve()
        if len(config_sha256) != 64:
            raise ValueError("promotion config hash must be SHA-256")
        if job_key is not None and (not job_key or ":" not in job_key):
            raise ValueError("promotion job key must be board-qualified")
        if not source.is_file():
            raise FileNotFoundError(f"collector database does not exist: {source}")

        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=30)) as src:
            src.execute("PRAGMA query_only=ON")
            src.execute("BEGIN")
            columns = {str(row[1]) for row in src.execute("PRAGMA table_info(postings)")}
            required = {
                "key", "board", "job_id", "url", "posted_at", "first_seen_at",
                "last_seen_at", "fetched_at", "raw_text", "raw_json", "content_hash",
                "fetch_status", "fetch_error",
            }
            if not required <= columns:
                raise ValueError(
                    f"collector postings schema missing columns: {sorted(required - columns)}"
                )
            schema = [
                {"name": row[1], "sql": row[3], "table": row[2], "type": row[0]}
                for row in src.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master "
                    "WHERE sql IS NOT NULL ORDER BY type,name"
                )
            ]
            key_where = " WHERE key=?" if job_key is not None else ""
            key_params: tuple[object, ...] = (job_key,) if job_key is not None else ()
            status_counts = {
                str(row[0]): int(row[1])
                for row in src.execute(
                    f"SELECT fetch_status,COUNT(*) FROM postings{key_where} "
                    "GROUP BY fetch_status",
                    key_params,
                )
            }
            rows = [
                {
                    "key": row[0],
                    "board": row[1],
                    "job_id": row[2],
                    "url": row[3],
                    "posted_at": row[4],
                    "first_seen_at": row[5],
                    "last_seen_at": row[6],
                    "fetched_at": row[7],
                    "raw_text": row[8],
                    "raw_json": row[9],
                    "content_hash": row[10],
                }
                for row in src.execute(
                    """SELECT key,board,job_id,url,posted_at,first_seen_at,last_seen_at,
                              fetched_at,raw_text,raw_json,content_hash
                       FROM postings WHERE fetch_status='fetched' AND content_hash IS NOT NULL
                       """ + (" AND key=?" if job_key is not None else "") + " ORDER BY key",
                    key_params,
                )
            ]
            if job_key is not None and sum(status_counts.values()) != 1:
                raise KeyError(f"collector database has no exact vacancy: {job_key}")
            if job_key is not None and not rows:
                raise ValueError(f"exact collector vacancy is not fetched: {job_key}")
            for row in rows:
                if row["key"] != f"{row['board']}:{row['job_id']}":
                    raise ValueError(f"collector row has inconsistent identity: {row['key']}")
                if row["raw_json"] is not None and not isinstance(json.loads(row["raw_json"]), dict):
                    raise ValueError(f"collector raw JSON must be an object: {row['key']}")
                material = str(row["raw_text"] or "") + str(row["raw_json"] or "")
                digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
                if digest != row["content_hash"]:
                    raise ValueError(f"collector content hash mismatch: {row['key']}")
            src.commit()

        schema_sha256 = _canonical_hash(schema)
        content_sha256 = _canonical_hash(rows)
        path_sha256 = hashlib.sha256(str(source).encode("utf-8")).hexdigest()
        source_db_sha256 = _canonical_hash(
            {
                "content_sha256": content_sha256,
                "path_sha256": path_sha256,
                "schema_sha256": schema_sha256,
            }
        )
        imported = updated = unchanged = 0
        if source == target:
            unchanged = len(rows)
        else:
            with closing(self.connect()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                for row in rows:
                    existing = conn.execute(
                        "SELECT content_hash FROM postings WHERE key=?", (row["key"],)
                    ).fetchone()
                    if existing is None:
                        imported += 1
                    elif existing[0] == row["content_hash"]:
                        unchanged += 1
                    else:
                        updated += 1
                    conn.execute(
                        """INSERT INTO postings(
                             key,board,job_id,url,posted_at,first_seen_at,last_seen_at,fetched_at,
                             raw_text,raw_json,content_hash,fetch_status,fetch_error
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'fetched',NULL)
                           ON CONFLICT(key) DO UPDATE SET
                             board=excluded.board,job_id=excluded.job_id,url=excluded.url,
                             posted_at=COALESCE(excluded.posted_at,postings.posted_at),
                             last_seen_at=excluded.last_seen_at,fetched_at=excluded.fetched_at,
                             raw_text=excluded.raw_text,raw_json=excluded.raw_json,
                             content_hash=excluded.content_hash,fetch_status='fetched',fetch_error=NULL""",
                        (
                            row["key"], row["board"], row["job_id"], row["url"],
                            row["posted_at"], row["first_seen_at"], row["last_seen_at"],
                            row["fetched_at"], row["raw_text"], row["raw_json"],
                            row["content_hash"],
                        ),
                    )
        result: dict[str, object] = {
            "application_authority": False,
            "authority_scope": "state_promotion_only",
            "config_sha256": config_sha256,
            "eligible_fetched": len(rows),
            "excluded_discovered": status_counts.get("discovered", 0),
            "excluded_error": status_counts.get("error", 0),
            "imported": imported,
            "schema_version": "market-aligner.collection-promotion.v1",
            "source_content_sha256": content_sha256,
            "source_db_sha256": source_db_sha256,
            "source_path_sha256": path_sha256,
            "source_schema_sha256": schema_sha256,
            "source_total": sum(status_counts.values()),
            "unchanged": unchanged,
            "updated": updated,
        }
        if job_key is not None:
            result["job_key"] = job_key
        return result

    def claim_fetched_for_processing(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        worker_id: str,
        limit: int,
        lease_seconds: int = 900,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> list[RawPosting]:
        """Atomically lease one shard of current fetched snapshots."""

        if limit <= 0 or lease_seconds <= 0:
            raise ValueError("processing shard and lease must be positive")
        now = time.time()
        lease_until = now + lease_seconds
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        claimed: list[RawPosting] = []
        with closing(self.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                   SELECT p.key,p.board,p.job_id,p.url,p.fetched_at,p.raw_text,
                          p.raw_json,p.content_hash
                   FROM scoped p
                   LEFT JOIN processing_jobs q
                     ON q.profile_id=? AND q.track=? AND q.job_key=p.key
                    AND q.authority_sha256=? AND q.source_content_sha256=p.content_hash
                    AND q.processing_config_sha256=?
                   WHERE p.fetch_status='fetched' AND p.content_hash IS NOT NULL
                     AND (q.status IS NULL OR q.status='failed'
                          OR (q.status='leased' AND q.lease_until<?))
                   ORDER BY p.key LIMIT ?""",
                (
                    *scope_params, profile_id, track, authority_sha256,
                    processing_config_sha256, now, limit,
                ),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """INSERT INTO processing_jobs(
                         profile_id,track,job_key,authority_sha256,source_content_sha256,
                         processing_config_sha256,status,lease_owner,lease_until,
                         result_json,error
                       ) VALUES(?,?,?,?,?,?,'leased',?,?,NULL,NULL)
                       ON CONFLICT(
                         profile_id,track,job_key,authority_sha256,source_content_sha256,
                         processing_config_sha256
                       )
                       DO UPDATE SET status='leased',lease_owner=excluded.lease_owner,
                         lease_until=excluded.lease_until,result_json=NULL,error=NULL,
                         updated_at=CURRENT_TIMESTAMP""",
                    (
                        profile_id,
                        track,
                        row[0],
                        authority_sha256,
                        row[7],
                        processing_config_sha256,
                        worker_id,
                        lease_until,
                    ),
                )
                claimed.append(
                    RawPosting(
                        board=row[1],
                        job_id=row[2],
                        url=row[3],
                        fetched_at=row[4] or "",
                        raw_text=row[5],
                        raw_json=json.loads(row[6]) if row[6] else None,
                        content_sha256=row[7],
                    )
                )
        return claimed

    def complete_processing(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        authority_sha256: str,
        source_content_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        worker_id: str,
        result: dict[str, object],
    ) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE processing_jobs SET status='completed',lease_owner=NULL,
                     lease_until=NULL,result_json=?,error=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND track=? AND job_key=? AND authority_sha256=?
                     AND source_content_sha256=? AND processing_config_sha256=?
                     AND status='leased' AND lease_owner=?""",
                (
                    payload,
                    profile_id,
                    track,
                    job_key,
                    authority_sha256,
                    source_content_sha256,
                    processing_config_sha256,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("processing completion requires the active shard lease")

    def fail_processing(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        authority_sha256: str,
        source_content_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        worker_id: str,
        error: str,
    ) -> None:
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE processing_jobs SET status='failed',lease_owner=NULL,
                     lease_until=NULL,result_json=NULL,error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND track=? AND job_key=? AND authority_sha256=?
                     AND source_content_sha256=? AND processing_config_sha256=?
                     AND status='leased' AND lease_owner=?""",
                (
                    error[:2000],
                    profile_id,
                    track,
                    job_key,
                    authority_sha256,
                    source_content_sha256,
                    processing_config_sha256,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("processing failure requires the active shard lease")

    def completed_processing(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> list[dict[str, object]]:
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        with closing(self.connect()) as conn:
            rows = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                   SELECT q.result_json FROM processing_jobs q
                   JOIN scoped p ON p.key=q.job_key
                    AND p.content_hash=q.source_content_sha256
                   WHERE q.profile_id=? AND q.track=? AND q.authority_sha256=?
                     AND q.processing_config_sha256=?
                     AND q.status='completed' AND q.result_json IS NOT NULL
                   ORDER BY q.job_key""",
                (
                    *scope_params, profile_id, track, authority_sha256,
                    processing_config_sha256,
                ),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def processing_scope_counts(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> dict[str, int]:
        """Return exact current-snapshot counts without changing excluded rows."""

        includes = tuple(include_boards)
        excludes = tuple(exclude_boards)
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=includes,
            exclude_boards=excludes,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        board_where, board_params = _processing_board_where(includes, excludes)
        now = time.time()
        with closing(self.connect()) as conn:
            fetched_total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM postings WHERE fetch_status='fetched' "
                    "AND content_hash IS NOT NULL"
                ).fetchone()[0]
            )
            board_eligible = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM postings p WHERE {board_where}", board_params
                ).fetchone()[0]
            )
            row = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                    SELECT COUNT(*),
                      SUM(CASE WHEN q.status='completed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN q.status='leased' AND q.lease_until>=? THEN 1 ELSE 0 END),
                      SUM(CASE WHEN q.status='failed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN q.status IS NULL OR q.status='failed'
                                OR (q.status='leased' AND q.lease_until<?) THEN 1 ELSE 0 END)
                    FROM scoped p LEFT JOIN processing_jobs q
                     ON q.profile_id=? AND q.track=? AND q.job_key=p.key
                     AND q.authority_sha256=? AND q.source_content_sha256=p.content_hash
                     AND q.processing_config_sha256=?""",
                (
                    *scope_params, now, now, profile_id, track, authority_sha256,
                    processing_config_sha256,
                ),
            ).fetchone()
        scoped = int(row[0] or 0)
        return {
            "available": int(row[4] or 0),
            "board_eligible": board_eligible,
            "completed": int(row[1] or 0),
            "excluded_by_board": fetched_total - board_eligible,
            "excluded_by_limit": board_eligible - scoped,
            "failed": int(row[3] or 0),
            "fetched_total": fetched_total,
            "leased": int(row[2] or 0),
            "scope_eligible": scoped,
        }

    @contextmanager
    def processing_report_snapshot(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> Iterator[list[dict[str, object]]]:
        """Serialize canonical report snapshots across concurrent processing shards."""

        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    f"""WITH scoped AS ({scope_sql})
                       SELECT q.result_json FROM processing_jobs q
                       JOIN scoped p ON p.key=q.job_key
                        AND p.content_hash=q.source_content_sha256
                       WHERE q.profile_id=? AND q.track=? AND q.authority_sha256=?
                         AND q.processing_config_sha256=?
                         AND q.status='completed' AND q.result_json IS NOT NULL
                       ORDER BY q.job_key""",
                    (
                        *scope_params, profile_id, track, authority_sha256,
                        processing_config_sha256,
                    ),
                ).fetchall()
                yield [json.loads(row[0]) for row in rows]
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    def reusable_processing_result(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        authority_sha256: str,
        source_content_sha256: str,
        processing_config_sha256: str,
    ) -> dict[str, object] | None:
        """Return a prior exact-evidence result from another config identity.

        The caller must re-run all deterministic policy decisions.  This method
        only avoids repeating already accepted semantic extraction/alignment.
        """

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT result_json FROM processing_jobs
                   WHERE profile_id=? AND track=? AND job_key=?
                     AND authority_sha256=? AND source_content_sha256=?
                     AND processing_config_sha256!=?
                     AND status='completed' AND result_json IS NOT NULL
                   ORDER BY updated_at DESC, processing_config_sha256 DESC LIMIT 1""",
                (
                    profile_id, track, job_key, authority_sha256,
                    source_content_sha256, processing_config_sha256,
                ),
            ).fetchone()
        return None if row is None else json.loads(row[0])


def _processing_board_where(
    include_boards: Iterable[str],
    exclude_boards: Iterable[str],
    exact_job_key: str | None = None,
) -> tuple[str, tuple[object, ...]]:
    includes = tuple(sorted(set(include_boards)))
    excludes = tuple(sorted(set(exclude_boards)))
    conditions = ["p.fetch_status='fetched'", "p.content_hash IS NOT NULL"]
    params: list[object] = []
    if includes:
        conditions.append(f"p.board IN ({','.join('?' for _ in includes)})")
        params.extend(includes)
    if excludes:
        conditions.append(f"p.board NOT IN ({','.join('?' for _ in excludes)})")
        params.extend(excludes)
    if exact_job_key is not None:
        if not exact_job_key or ":" not in exact_job_key:
            raise ValueError("exact processing job key must be board-qualified")
        conditions.append("p.key=?")
        params.append(exact_job_key)
    return " AND ".join(conditions), tuple(params)


def _processing_scope_sql(
    *,
    include_boards: Iterable[str],
    exclude_boards: Iterable[str],
    max_total: int | None,
    exact_job_key: str | None = None,
) -> tuple[str, tuple[object, ...]]:
    if max_total is not None and max_total <= 0:
        raise ValueError("processing max_total must be positive when set")
    where, params = _processing_board_where(
        include_boards, exclude_boards, exact_job_key
    )
    return (
        f"SELECT p.* FROM postings p WHERE {where} ORDER BY p.key LIMIT ?",
        (*params, -1 if max_total is None else max_total),
    )
