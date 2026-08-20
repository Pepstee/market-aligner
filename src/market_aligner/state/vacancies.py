"""Persistent, append-preserving storage for the collection pipeline."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from market_aligner.domain.contracts import JobUrl, RawPosting, read_jsonl, write_jsonl
from market_aligner.state.importers import iter_raw_cache_roots


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
CREATE TABLE IF NOT EXISTS processing_jobs (
  profile_id TEXT NOT NULL,
  track TEXT NOT NULL,
  job_key TEXT NOT NULL,
  authority_sha256 TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('leased','completed','failed')),
  lease_owner TEXT,
  lease_until REAL,
  result_json TEXT,
  error TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,track,job_key,authority_sha256,source_content_sha256),
  FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS processing_jobs_resume
  ON processing_jobs(profile_id,track,authority_sha256,status,lease_until);
"""


class JobDatabase:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn, conn:
            conn.executescript(SCHEMA)

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
        material = (row.raw_text or "") + (raw_json or "")
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """UPDATE postings SET fetched_at=?,raw_text=?,raw_json=?,content_hash=?,
                   fetch_status='fetched',fetch_error=NULL WHERE key=?""",
                (row.fetched_at, row.raw_text, raw_json, digest, row.key),
            )

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

    def claim_fetched_for_processing(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        worker_id: str,
        limit: int,
        lease_seconds: int = 900,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
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
                   WHERE p.fetch_status='fetched' AND p.content_hash IS NOT NULL
                     AND (q.status IS NULL OR q.status='failed'
                          OR (q.status='leased' AND q.lease_until<?))
                   ORDER BY p.key LIMIT ?""",
                (*scope_params, profile_id, track, authority_sha256, now, limit),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """INSERT INTO processing_jobs(
                         profile_id,track,job_key,authority_sha256,source_content_sha256,
                         status,lease_owner,lease_until,result_json,error
                       ) VALUES(?,?,?,?,?,'leased',?,?,NULL,NULL)
                       ON CONFLICT(profile_id,track,job_key,authority_sha256,source_content_sha256)
                       DO UPDATE SET status='leased',lease_owner=excluded.lease_owner,
                         lease_until=excluded.lease_until,result_json=NULL,error=NULL,
                         updated_at=CURRENT_TIMESTAMP""",
                    (
                        profile_id,
                        track,
                        row[0],
                        authority_sha256,
                        row[7],
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
        worker_id: str,
        result: dict[str, object],
    ) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE processing_jobs SET status='completed',lease_owner=NULL,
                     lease_until=NULL,result_json=?,error=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND track=? AND job_key=? AND authority_sha256=?
                     AND source_content_sha256=? AND status='leased' AND lease_owner=?""",
                (
                    payload,
                    profile_id,
                    track,
                    job_key,
                    authority_sha256,
                    source_content_sha256,
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
        worker_id: str,
        error: str,
    ) -> None:
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE processing_jobs SET status='failed',lease_owner=NULL,
                     lease_until=NULL,result_json=NULL,error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND track=? AND job_key=? AND authority_sha256=?
                     AND source_content_sha256=? AND status='leased' AND lease_owner=?""",
                (
                    error[:2000],
                    profile_id,
                    track,
                    job_key,
                    authority_sha256,
                    source_content_sha256,
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
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
    ) -> list[dict[str, object]]:
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
        )
        with closing(self.connect()) as conn:
            rows = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                   SELECT q.result_json FROM processing_jobs q
                   JOIN scoped p ON p.key=q.job_key
                    AND p.content_hash=q.source_content_sha256
                   WHERE q.profile_id=? AND q.track=? AND q.authority_sha256=?
                     AND q.status='completed' AND q.result_json IS NOT NULL
                   ORDER BY q.job_key""",
                (*scope_params, profile_id, track, authority_sha256),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def processing_scope_counts(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
    ) -> dict[str, int]:
        """Return exact current-snapshot counts without changing excluded rows."""

        includes = tuple(include_boards)
        excludes = tuple(exclude_boards)
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=includes,
            exclude_boards=excludes,
            max_total=max_total,
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
                     AND q.authority_sha256=? AND q.source_content_sha256=p.content_hash""",
                (*scope_params, now, now, profile_id, track, authority_sha256),
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
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
    ) -> Iterator[list[dict[str, object]]]:
        """Serialize canonical report snapshots across concurrent processing shards."""

        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
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
                         AND q.status='completed' AND q.result_json IS NOT NULL
                       ORDER BY q.job_key""",
                    (*scope_params, profile_id, track, authority_sha256),
                ).fetchall()
                yield [json.loads(row[0]) for row in rows]
                conn.commit()
            except BaseException:
                conn.rollback()
                raise


def _processing_board_where(
    include_boards: Iterable[str], exclude_boards: Iterable[str]
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
    return " AND ".join(conditions), tuple(params)


def _processing_scope_sql(
    *,
    include_boards: Iterable[str],
    exclude_boards: Iterable[str],
    max_total: int | None,
) -> tuple[str, tuple[object, ...]]:
    if max_total is not None and max_total <= 0:
        raise ValueError("processing max_total must be positive when set")
    where, params = _processing_board_where(include_boards, exclude_boards)
    return (
        f"SELECT p.* FROM postings p WHERE {where} ORDER BY p.key LIMIT ?",
        (*params, -1 if max_total is None else max_total),
    )
