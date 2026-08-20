"""Auditable deployment plans, health gates, events, and rollback state.

This borrows deployment-control concepts without importing a PaaS.  It does
not execute deployments; an external adapter must perform the mutation and
record its receipt before promotion.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class HealthCheckDefinition:
    check_id: str
    kind: str
    target: str
    required: bool = True

    def __post_init__(self) -> None:
        if not self.check_id.strip() or not self.kind.strip() or not self.target.strip():
            raise ValueError("health check id, kind and target are required")


@dataclass(frozen=True)
class DeploymentPlan:
    service: str
    release_id: str
    artifact_digest: str
    config_hash: str
    checks: tuple[HealthCheckDefinition, ...]
    migration_version: str | None = None

    def __post_init__(self) -> None:
        if not self.service.strip() or not self.release_id.strip():
            raise ValueError("service and release_id are required")
        if not DIGEST_RE.fullmatch(self.artifact_digest):
            raise ValueError("artifact must be pinned by a sha256 digest")
        if not re.fullmatch(r"[0-9a-f]{64}", self.config_hash):
            raise ValueError("config_hash must be a lowercase sha256 hex digest")
        check_ids = [check.check_id for check in self.checks]
        if not check_ids or len(check_ids) != len(set(check_ids)):
            raise ValueError("deployment checks must be non-empty and uniquely identified")

    @property
    def plan_hash(self) -> str:
        body = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


DEPLOYMENT_SCHEMA = """
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS career_deployment_releases (
  release_id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  artifact_digest TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  previous_release_id TEXT REFERENCES career_deployment_releases(release_id),
  status TEXT NOT NULL CHECK(status IN ('staged','active','superseded','rolled_back','failed')),
  external_receipt TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS career_deployment_service_status
  ON career_deployment_releases(service,status);

CREATE TABLE IF NOT EXISTS career_deployment_checks (
  release_id TEXT NOT NULL REFERENCES career_deployment_releases(release_id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  required INTEGER NOT NULL CHECK(required IN (0,1)),
  status TEXT NOT NULL CHECK(status IN ('pending','passed','failed')),
  detail TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(release_id,check_id)
);

CREATE TABLE IF NOT EXISTS career_deployment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service TEXT NOT NULL,
  release_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class DeploymentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(DEPLOYMENT_SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def stage(self, plan: DeploymentPlan) -> bool:
        """Record an immutable staged release; exact replays are idempotent."""
        plan_json = json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"))
        with self.connection() as conn:
            existing = conn.execute(
                "SELECT plan_hash FROM career_deployment_releases WHERE release_id=?",
                (plan.release_id,),
            ).fetchone()
            if existing is not None:
                if existing["plan_hash"] != plan.plan_hash:
                    raise ValueError("release_id already exists with a different immutable plan")
                return False
            active = conn.execute(
                "SELECT release_id FROM career_deployment_releases WHERE service=? AND status='active'",
                (plan.service,),
            ).fetchone()
            previous = str(active["release_id"]) if active else None
            conn.execute(
                """INSERT INTO career_deployment_releases(
                     release_id,service,artifact_digest,config_hash,plan_hash,plan_json,
                     previous_release_id,status
                   ) VALUES(?,?,?,?,?,?,?,'staged')""",
                (
                    plan.release_id,
                    plan.service,
                    plan.artifact_digest,
                    plan.config_hash,
                    plan.plan_hash,
                    plan_json,
                    previous,
                ),
            )
            conn.executemany(
                """INSERT INTO career_deployment_checks(release_id,check_id,required,status)
                   VALUES(?,?,?,'pending')""",
                [(plan.release_id, check.check_id, int(check.required)) for check in plan.checks],
            )
            conn.execute(
                """INSERT INTO career_deployment_events(
                     service,release_id,event_type,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (
                    plan.service,
                    plan.release_id,
                    "release_staged",
                    json.dumps({"plan_hash": plan.plan_hash, "previous_release_id": previous}),
                    f"deployment-stage:{plan.release_id}:{plan.plan_hash}",
                ),
            )
        return True

    def record_external_receipt(self, release_id: str, receipt: str) -> None:
        if not receipt.strip():
            raise ValueError("external deployment receipt is required")
        with self.connection() as conn:
            row = self._release(conn, release_id)
            existing = row["external_receipt"]
            if existing not in (None, receipt):
                raise ValueError("deployment receipt is immutable")
            conn.execute(
                "UPDATE career_deployment_releases SET external_receipt=?,updated_at=CURRENT_TIMESTAMP WHERE release_id=?",
                (receipt, release_id),
            )
            conn.execute(
                """INSERT OR IGNORE INTO career_deployment_events(
                     service,release_id,event_type,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (
                    row["service"],
                    release_id,
                    "external_deployment_receipted",
                    json.dumps({"receipt_hash": hashlib.sha256(receipt.encode()).hexdigest()}),
                    f"deployment-receipt:{release_id}:{hashlib.sha256(receipt.encode()).hexdigest()}",
                ),
            )

    def record_check(self, release_id: str, check_id: str, *, passed: bool, detail: str = "") -> None:
        with self.connection() as conn:
            row = self._release(conn, release_id)
            check = conn.execute(
                "SELECT 1 FROM career_deployment_checks WHERE release_id=? AND check_id=?",
                (release_id, check_id),
            ).fetchone()
            if check is None:
                raise KeyError(f"unknown health check: {check_id}")
            status = "passed" if passed else "failed"
            conn.execute(
                """UPDATE career_deployment_checks SET status=?,detail=?,updated_at=CURRENT_TIMESTAMP
                   WHERE release_id=? AND check_id=?""",
                (status, detail, release_id, check_id),
            )
            payload = {"check_id": check_id, "status": status, "detail": detail}
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            conn.execute(
                """INSERT OR IGNORE INTO career_deployment_events(
                     service,release_id,event_type,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (
                    row["service"], release_id, "health_check_recorded",
                    json.dumps(payload, sort_keys=True), f"deployment-check:{release_id}:{digest}",
                ),
            )

    def promote(self, release_id: str) -> None:
        """Activate only an externally receipted release whose required checks passed."""
        with self.connection() as conn:
            row = self._release(conn, release_id)
            if row["status"] == "active":
                return
            if row["status"] != "staged":
                raise RuntimeError(f"cannot promote release in state {row['status']}")
            if not row["external_receipt"]:
                raise RuntimeError("promotion requires an external deployment receipt")
            failed = conn.execute(
                """SELECT check_id,status FROM career_deployment_checks
                   WHERE release_id=? AND required=1 AND status!='passed'""",
                (release_id,),
            ).fetchall()
            if failed:
                summary = ", ".join(f"{item['check_id']}={item['status']}" for item in failed)
                raise RuntimeError(f"required health checks have not passed: {summary}")
            previous = conn.execute(
                "SELECT release_id FROM career_deployment_releases WHERE service=? AND status='active'",
                (row["service"],),
            ).fetchone()
            if previous:
                conn.execute(
                    "UPDATE career_deployment_releases SET status='superseded',updated_at=CURRENT_TIMESTAMP WHERE release_id=?",
                    (previous["release_id"],),
                )
                conn.execute(
                    "UPDATE career_deployment_releases SET previous_release_id=? WHERE release_id=?",
                    (previous["release_id"], release_id),
                )
            conn.execute(
                "UPDATE career_deployment_releases SET status='active',updated_at=CURRENT_TIMESTAMP WHERE release_id=?",
                (release_id,),
            )
            conn.execute(
                """INSERT OR IGNORE INTO career_deployment_events(
                     service,release_id,event_type,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (
                    row["service"], release_id, "release_promoted",
                    json.dumps({"previous_release_id": previous["release_id"] if previous else None}),
                    f"deployment-promote:{release_id}",
                ),
            )

    def rollback(self, service: str, *, reason: str) -> str:
        if not reason.strip():
            raise ValueError("rollback reason is required")
        with self.connection() as conn:
            active = conn.execute(
                """SELECT * FROM career_deployment_releases
                   WHERE service=? AND status='active'""",
                (service,),
            ).fetchone()
            if active is None:
                raise RuntimeError("service has no active release")
            previous_id = active["previous_release_id"]
            if not previous_id:
                raise RuntimeError("active release has no rollback target")
            previous = self._release(conn, str(previous_id))
            conn.execute(
                "UPDATE career_deployment_releases SET status='rolled_back',updated_at=CURRENT_TIMESTAMP WHERE release_id=?",
                (active["release_id"],),
            )
            conn.execute(
                "UPDATE career_deployment_releases SET status='active',updated_at=CURRENT_TIMESTAMP WHERE release_id=?",
                (previous["release_id"],),
            )
            reason_hash = hashlib.sha256(reason.encode()).hexdigest()
            conn.execute(
                """INSERT OR IGNORE INTO career_deployment_events(
                     service,release_id,event_type,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (
                    service, active["release_id"], "release_rolled_back",
                    json.dumps({"target_release_id": previous["release_id"], "reason": reason}),
                    f"deployment-rollback:{active['release_id']}:{previous['release_id']}:{reason_hash}",
                ),
            )
            return str(previous["release_id"])

    @staticmethod
    def _release(conn: sqlite3.Connection, release_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM career_deployment_releases WHERE release_id=?", (release_id,)
        ).fetchone()
        if row is None:
            raise KeyError(release_id)
        return row

