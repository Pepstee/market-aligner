"""Persistent, append-preserving storage for the collection pipeline."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

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
