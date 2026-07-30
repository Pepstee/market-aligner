"""Durable local-only JAA-10 fixture observation records.

The ledger records host-generated UTC wall-clock times inside SQLite write
transactions and uses a per-process monotonic witness.  The host clock is not
an external time authority, and integrity verification assumes a
non-privileged filesystem writer: a privileged writer can perform a surgical
partial rewrite that this local design cannot detect.

This module cannot browse, submit, consume release tokens, handle credentials,
evaluate metrics, or certify any JAA slice.  Live time-separated shadow
evidence remains uncollected.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    ShadowObservation,
)


STORE_SCHEMA_VERSION = "jaa10.shadow-observation-ledger.v1"
RECEIPT_SCHEMA_VERSION = "jaa10.shadow-observation-ledger-receipt.v1"
POLICY_VERSION = "jaa10.shadow-observation-ledger-policy.v1"
GENESIS_PREVIOUS_RECEIPT = "0" * 64
FILESYSTEM_WRITER_LIMIT = (
    "surgical_partial_rewrite_undetectable_no_local_mitigation"
)
CLOCK_AUTHENTICATION = "local_host_wall_clock_not_external_time_authority"
MONOTONIC_WITNESS_SCOPE = (
    "single_process_only_not_comparable_across_sessions"
)
ASSESSMENT = "withheld_pending_fable_live_execution_gate"
SPAN_MEANING = (
    "local_host_wall_clock_span_fixture_scope_only_not_live_time_"
    "separation_evidence"
)
SQLITE_TIMEOUT_SECONDS = 10.0

_RECEIPT_DOMAIN = b"jaa10-shadow-observation-ledger-receipt-v1\0"
_INSTANCE_DOMAIN = b"jaa10-shadow-observation-ledger-instance-v1\0"
_SESSION_DOMAIN = b"jaa10-shadow-observation-ledger-session-v1\0"
_PROCESS_DOMAIN = b"jaa10-shadow-observation-ledger-process-v1\0"
_STORE_HANDLE_DOMAIN = b"jaa10-shadow-observation-ledger-handle-v1\0"


class ObservationLedgerError(RuntimeError):
    """Base error for the local fixture observation ledger."""


class ObservationLedgerIntegrityError(ObservationLedgerError):
    """The durable ledger cannot be trusted under its declared assumptions."""


class ObservationLedgerStateError(ObservationLedgerError):
    """A requested append violates the ledger state machine."""


@dataclass(frozen=True)
class ObservationLedgerIdentity:
    contract_sha256: str
    ledger_instance_id: str
    genesis_receipt_sha256: str
    fixture_policy_sha256: str

    def __post_init__(self) -> None:
        _digest(self.contract_sha256, "contract hash")
        _digest(self.ledger_instance_id, "ledger instance ID")
        _digest(self.genesis_receipt_sha256, "genesis receipt hash")
        _digest(self.fixture_policy_sha256, "fixture policy hash")


@dataclass(frozen=True)
class ObservationSession:
    ledger_instance_id: str
    session_id: str
    process_token: str
    store_handle_token: str
    open_receipt_sha256: str

    def __post_init__(self) -> None:
        _digest(self.ledger_instance_id, "session ledger instance ID")
        _digest(self.session_id, "session ID")
        _digest(self.process_token, "session process token")
        _digest(self.store_handle_token, "session store handle token")
        _digest(self.open_receipt_sha256, "session-open receipt hash")


@dataclass(frozen=True)
class ObservationLedgerReceipt:
    receipt_sha256: str
    document: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.receipt_sha256, "receipt hash")
        immutable = MappingProxyType(dict(self.document))
        object.__setattr__(self, "document", immutable)
        if _receipt_hash(dict(immutable)) != self.receipt_sha256:
            raise ObservationLedgerIntegrityError(
                "observation ledger receipt content hash differs"
            )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(
        _canonical_json(value).encode("utf-8")
    ).hexdigest()


def _domain_hash(domain: bytes, payload: bytes) -> str:
    digest = hashlib.sha256(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


_PROCESS_TOKEN = _domain_hash(_PROCESS_DOMAIN, os.urandom(32))


def _receipt_hash(document: Mapping[str, Any]) -> str:
    return _domain_hash(
        _RECEIPT_DOMAIN,
        _canonical_json(dict(document)).encode("utf-8"),
    )


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label} must be lowercase SHA-256")
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be lowercase SHA-256") from exc
    if parsed.hex() != value:
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _database_path(value: str | Path, *, must_exist: bool) -> Path:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or raw == ":memory:"
        or raw.startswith("file:")
        or "\x00" in raw
    ):
        raise ValueError(
            "observation ledger requires a plain filesystem SQLite path"
        )
    unresolved = Path(raw).expanduser()
    if unresolved.is_symlink():
        raise ValueError("observation ledger database path cannot be a symlink")
    path = unresolved.resolve(strict=False)
    if must_exist:
        if not path.is_file():
            raise ObservationLedgerIntegrityError(
                "observation ledger database is missing or replaced"
            )
    elif path.exists():
        raise FileExistsError(
            "observation ledger database must not already exist"
        )
    return path


def _utc(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ObservationLedgerIntegrityError(
            f"{label} is not an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ObservationLedgerIntegrityError(
            f"{label} must include a timezone"
        )
    normalized = parsed.astimezone(timezone.utc)
    if normalized.isoformat() != value:
        raise ObservationLedgerIntegrityError(
            f"{label} must be canonical UTC"
        )
    return normalized


def ledger_policy_document() -> dict[str, object]:
    """Return the immutable, non-authorizing Phase-A fixture policy."""
    return {
        "schema_version": STORE_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "fixture_scope_only": True,
        "external_action_capability": False,
        "live_time_separated_execution": "not_collected",
        "metrics_evaluated": False,
        "production_certification": "withheld",
        "certifies_slice": False,
        "clock_authentication": CLOCK_AUTHENTICATION,
        "monotonic_witness_scope": MONOTONIC_WITNESS_SCOPE,
        "filesystem_privileged_writer_limit": FILESYSTEM_WRITER_LIMIT,
    }


def _process_token() -> str:
    return _PROCESS_TOKEN


def _store_handle_token() -> str:
    return _domain_hash(_STORE_HANDLE_DOMAIN, os.urandom(32))


def _session_id() -> str:
    return _domain_hash(_SESSION_DOMAIN, os.urandom(32))


def _host_time() -> tuple[str, int]:
    recorded_at = datetime.now(timezone.utc).isoformat()
    monotonic_ns = time.monotonic_ns()
    if monotonic_ns < 1:
        raise ObservationLedgerIntegrityError(
            "host monotonic witness is invalid"
        )
    return recorded_at, monotonic_ns


def _canonical_observation(observation: ShadowObservation) -> None:
    if not isinstance(observation, ShadowObservation):
        raise TypeError(
            "observation ledger requires a typed shadow observation"
        )
    expected = FROZEN_SHADOW_CONTRACT
    actual_lineage = (
        observation.workflow_sha256,
        observation.receipt_id,
        observation.receipt_payload_sha256,
        observation.field_map_sha256,
        observation.screenshot_sha256,
        observation.normalized_submit_event_sha256,
    )
    canonical_lineage = (
        expected.workflow_sha256,
        expected.receipt_id,
        expected.receipt_payload_sha256,
        expected.field_map_sha256,
        expected.screenshot_sha256,
        expected.submit_event_sha256,
    )
    if actual_lineage != canonical_lineage:
        raise ValueError(
            "observation ledger requires the canonical frozen contract lineage"
        )


def _receipt_document(
    *,
    event_type: str,
    sequence: int,
    previous_receipt_sha256: str,
    contract_sha256: str,
    ledger_instance_id: str,
    session_id: str | None,
    host_recorded_at_utc: str,
    host_monotonic_ns: int,
    process_token: str,
    genesis_nonce: str | None = None,
    fixture_policy_sha256: str | None = None,
    observation: ShadowObservation | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "event_type": event_type,
        "sequence": sequence,
        "previous_receipt_sha256": previous_receipt_sha256,
        "contract_sha256": contract_sha256,
        "ledger_instance_id": ledger_instance_id,
        "session_id": session_id,
        "host_recorded_at_utc": host_recorded_at_utc,
        "host_monotonic_ns": host_monotonic_ns,
        "process_token": process_token,
    }
    if event_type == "genesis":
        document["genesis_nonce"] = genesis_nonce
        document["fixture_policy_sha256"] = fixture_policy_sha256
    elif event_type == "observation_recorded":
        if observation is None:
            raise ObservationLedgerIntegrityError(
                "observation receipt requires a typed observation"
            )
        document["observation_id"] = observation.observation_id
        document["observation_sha256"] = observation.observation_sha256
        document["source_observed_at"] = observation.observed_at
    return document


class ShadowObservationLedger:
    """Pinned, append-only, fixture-scope-only observation ledger."""

    def __init__(
        self,
        database_path: Path,
        identity: ObservationLedgerIdentity,
        process_token: str,
        store_handle_token: str,
    ) -> None:
        self._database_path = database_path
        self.identity = identity
        self._process_token = process_token
        self._store_handle_token = store_handle_token

    @property
    def database_path(self) -> Path:
        return self._database_path

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        *,
        contract_sha256: str,
    ) -> ShadowObservationLedger:
        path = _database_path(database_path, must_exist=False)
        canonical_contract = FROZEN_SHADOW_CONTRACT.contract_sha256
        if contract_sha256 != canonical_contract:
            raise ValueError(
                "observation ledger requires the canonical frozen contract"
            )
        policy = ledger_policy_document()
        fixture_policy_sha256 = _content_hash(policy)
        genesis_nonce = os.urandom(32).hex()
        ledger_instance_id = _domain_hash(
            _INSTANCE_DOMAIN,
            bytes.fromhex(genesis_nonce),
        )
        process_token = _process_token()
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = cls._new_connection(path)
        try:
            connection.executescript(
                """
                CREATE TABLE ledger_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    contract_sha256 TEXT NOT NULL,
                    ledger_instance_id TEXT NOT NULL,
                    genesis_nonce TEXT NOT NULL,
                    genesis_receipt_sha256 TEXT NOT NULL,
                    fixture_policy_json TEXT NOT NULL,
                    fixture_policy_sha256 TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                CREATE TABLE ledger_receipt (
                    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
                    event_type TEXT NOT NULL CHECK (
                        event_type IN (
                            'genesis',
                            'session_open',
                            'observation_recorded'
                        )
                    ),
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    previous_receipt_sha256 TEXT NOT NULL,
                    session_id TEXT,
                    host_recorded_at_utc TEXT NOT NULL,
                    host_monotonic_ns INTEGER NOT NULL
                        CHECK (host_monotonic_ns >= 1),
                    process_token TEXT NOT NULL,
                    observation_id TEXT,
                    observation_sha256 TEXT,
                    source_observed_at TEXT,
                    content_json TEXT NOT NULL
                );
                CREATE UNIQUE INDEX one_session_open
                    ON ledger_receipt(session_id)
                    WHERE event_type = 'session_open';
                CREATE UNIQUE INDEX one_observation_per_session
                    ON ledger_receipt(session_id)
                    WHERE event_type = 'observation_recorded';
                CREATE UNIQUE INDEX unique_observation_sha256
                    ON ledger_receipt(observation_sha256)
                    WHERE event_type = 'observation_recorded';
                CREATE TRIGGER ledger_metadata_no_update
                    BEFORE UPDATE ON ledger_metadata
                    BEGIN
                        SELECT RAISE(ABORT, 'ledger metadata is append-only');
                    END;
                CREATE TRIGGER ledger_metadata_no_delete
                    BEFORE DELETE ON ledger_metadata
                    BEGIN
                        SELECT RAISE(ABORT, 'ledger metadata is append-only');
                    END;
                CREATE TRIGGER ledger_receipt_no_update
                    BEFORE UPDATE ON ledger_receipt
                    BEGIN
                        SELECT RAISE(ABORT, 'ledger receipts are append-only');
                    END;
                CREATE TRIGGER ledger_receipt_no_delete
                    BEFORE DELETE ON ledger_receipt
                    BEGIN
                        SELECT RAISE(ABORT, 'ledger receipts are append-only');
                    END;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            host_time, monotonic_ns = _host_time()
            genesis_document = _receipt_document(
                event_type="genesis",
                sequence=1,
                previous_receipt_sha256=GENESIS_PREVIOUS_RECEIPT,
                contract_sha256=canonical_contract,
                ledger_instance_id=ledger_instance_id,
                session_id=None,
                host_recorded_at_utc=host_time,
                host_monotonic_ns=monotonic_ns,
                process_token=process_token,
                genesis_nonce=genesis_nonce,
                fixture_policy_sha256=fixture_policy_sha256,
            )
            genesis_receipt_sha256 = _receipt_hash(genesis_document)
            identity = ObservationLedgerIdentity(
                canonical_contract,
                ledger_instance_id,
                genesis_receipt_sha256,
                fixture_policy_sha256,
            )
            connection.execute(
                """
                INSERT INTO ledger_metadata (
                    singleton, schema_version, policy_version,
                    contract_sha256, ledger_instance_id, genesis_nonce,
                    genesis_receipt_sha256, fixture_policy_json,
                    fixture_policy_sha256, created_at_utc
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    STORE_SCHEMA_VERSION,
                    POLICY_VERSION,
                    canonical_contract,
                    ledger_instance_id,
                    genesis_nonce,
                    genesis_receipt_sha256,
                    _canonical_json(policy),
                    fixture_policy_sha256,
                    host_time,
                ),
            )
            cls._insert_receipt(
                connection,
                genesis_receipt_sha256,
                genesis_document,
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            connection.close()
            cls._remove_failed_database(path)
            raise
        finally:
            connection.close()
        store = cls(path, identity, process_token, _store_handle_token())
        store.verify()
        return store

    @classmethod
    def open(
        cls,
        database_path: str | Path,
        *,
        identity: ObservationLedgerIdentity,
    ) -> ShadowObservationLedger:
        path = _database_path(database_path, must_exist=True)
        store = cls(
            path,
            identity,
            _process_token(),
            _store_handle_token(),
        )
        store.verify()
        return store

    def begin_session(self) -> ObservationSession:
        connection = self._open_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            receipts = self._verified_receipts(connection)
            host_time, monotonic_ns = self._append_time(receipts)
            session_id = _session_id()
            sequence = len(receipts) + 1
            previous = receipts[-1].receipt_sha256
            document = _receipt_document(
                event_type="session_open",
                sequence=sequence,
                previous_receipt_sha256=previous,
                contract_sha256=self.identity.contract_sha256,
                ledger_instance_id=self.identity.ledger_instance_id,
                session_id=session_id,
                host_recorded_at_utc=host_time,
                host_monotonic_ns=monotonic_ns,
                process_token=self._process_token,
            )
            receipt_sha256 = _receipt_hash(document)
            self._insert_receipt(connection, receipt_sha256, document)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        self.verify()
        return ObservationSession(
            self.identity.ledger_instance_id,
            session_id,
            self._process_token,
            self._store_handle_token,
            receipt_sha256,
        )

    def record_observation(
        self,
        session: ObservationSession,
        observation: ShadowObservation,
    ) -> ObservationLedgerReceipt:
        _canonical_observation(observation)
        if not isinstance(session, ObservationSession):
            raise TypeError(
                "observation append requires a typed session handle"
            )
        if (
            session.ledger_instance_id != self.identity.ledger_instance_id
            or session.process_token != self._process_token
            or session.store_handle_token != self._store_handle_token
        ):
            raise ObservationLedgerStateError(
                "observation session handle is stale or belongs elsewhere"
            )
        connection = self._open_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            receipts = self._verified_receipts(connection)
            session_rows = [
                receipt
                for receipt in receipts
                if receipt.document.get("session_id") == session.session_id
            ]
            if (
                len(session_rows) != 1
                or session_rows[0].document["event_type"] != "session_open"
                or session_rows[0].receipt_sha256
                != session.open_receipt_sha256
            ):
                raise ObservationLedgerStateError(
                    "observation session is missing, stale or already used"
                )
            host_time, monotonic_ns = self._append_time(receipts)
            sequence = len(receipts) + 1
            document = _receipt_document(
                event_type="observation_recorded",
                sequence=sequence,
                previous_receipt_sha256=receipts[-1].receipt_sha256,
                contract_sha256=self.identity.contract_sha256,
                ledger_instance_id=self.identity.ledger_instance_id,
                session_id=session.session_id,
                host_recorded_at_utc=host_time,
                host_monotonic_ns=monotonic_ns,
                process_token=self._process_token,
                observation=observation,
            )
            receipt_sha256 = _receipt_hash(document)
            self._insert_receipt(connection, receipt_sha256, document)
            connection.commit()
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ObservationLedgerStateError(
                "observation session or identity was already recorded"
            ) from exc
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        self.verify()
        return ObservationLedgerReceipt(receipt_sha256, document)

    def receipts(self) -> tuple[ObservationLedgerReceipt, ...]:
        connection = self._open_connection()
        try:
            return self._verified_receipts(connection)
        finally:
            connection.close()

    def summary(self) -> dict[str, object]:
        receipts = self.receipts()
        sessions = {
            receipt.document["session_id"]
            for receipt in receipts
            if receipt.document["event_type"] == "session_open"
        }
        observations = [
            receipt
            for receipt in receipts
            if receipt.document["event_type"] == "observation_recorded"
        ]
        observed_sessions = {
            receipt.document["session_id"] for receipt in observations
        }
        times = [
            _utc(
                str(receipt.document["host_recorded_at_utc"]),
                "observation host time",
            )
            for receipt in observations
        ]
        first = times[0].isoformat() if times else None
        last = times[-1].isoformat() if times else None
        span = (
            (times[-1] - times[0]).total_seconds()
            if len(times) > 1
            else 0.0
        )
        return {
            "record_count": len(observations),
            "session_count": len(sessions),
            "sessions_without_observation": len(
                sessions - observed_sessions
            ),
            "first_observation_host_recorded_at_utc": first,
            "last_observation_host_recorded_at_utc": last,
            "recorded_wall_clock_span_seconds": span,
            "span_meaning": SPAN_MEANING,
            "assessment": ASSESSMENT,
            "policy": ledger_policy_document(),
        }

    def verify(self) -> None:
        connection = self._open_connection()
        try:
            self._verified_receipts(connection)
        finally:
            connection.close()

    def _open_connection(self) -> sqlite3.Connection:
        _database_path(self._database_path, must_exist=True)
        try:
            return self._new_connection(self._database_path)
        except sqlite3.DatabaseError as exc:
            raise ObservationLedgerIntegrityError(
                "observation ledger database is missing or replaced"
            ) from exc

    def _verified_receipts(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[ObservationLedgerReceipt, ...]:
        try:
            return self._verify_connection(connection)
        except ObservationLedgerError:
            raise
        except sqlite3.DatabaseError as exc:
            raise ObservationLedgerIntegrityError(
                "observation ledger database is missing or replaced"
            ) from exc

    def _append_time(
        self,
        receipts: tuple[ObservationLedgerReceipt, ...],
    ) -> tuple[str, int]:
        host_time, monotonic_ns = _host_time()
        current = _utc(host_time, "captured host time")
        prior = _utc(
            str(receipts[-1].document["host_recorded_at_utc"]),
            "chain-head host time",
        )
        if current < prior:
            raise ObservationLedgerStateError(
                "host wall clock moved backwards before ledger append"
            )
        same_process = [
            int(receipt.document["host_monotonic_ns"])
            for receipt in receipts
            if receipt.document["process_token"] == self._process_token
        ]
        if same_process and monotonic_ns <= same_process[-1]:
            raise ObservationLedgerStateError(
                "host monotonic witness did not advance"
            )
        return host_time, monotonic_ns

    def _verify_connection(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[ObservationLedgerReceipt, ...]:
        rows = connection.execute(
            """
            SELECT singleton, schema_version, policy_version,
                   contract_sha256, ledger_instance_id, genesis_nonce,
                   genesis_receipt_sha256, fixture_policy_json,
                   fixture_policy_sha256, created_at_utc
              FROM ledger_metadata
            """
        ).fetchall()
        if len(rows) != 1:
            raise ObservationLedgerIntegrityError(
                "observation ledger metadata cardinality differs"
            )
        (
            singleton,
            schema_version,
            policy_version,
            contract_sha256,
            ledger_instance_id,
            genesis_nonce,
            genesis_receipt_sha256,
            policy_json,
            policy_sha256,
            created_at_utc,
        ) = rows[0]
        if singleton != 1:
            raise ObservationLedgerIntegrityError(
                "observation ledger metadata singleton differs"
            )
        policy = ledger_policy_document()
        canonical_policy_json = _canonical_json(policy)
        if (
            schema_version != STORE_SCHEMA_VERSION
            or policy_version != POLICY_VERSION
            or contract_sha256
            != FROZEN_SHADOW_CONTRACT.contract_sha256
            or contract_sha256 != self.identity.contract_sha256
            or ledger_instance_id != self.identity.ledger_instance_id
            or genesis_receipt_sha256
            != self.identity.genesis_receipt_sha256
            or policy_json != canonical_policy_json
            or policy_sha256 != _content_hash(policy)
            or policy_sha256 != self.identity.fixture_policy_sha256
        ):
            raise ObservationLedgerIntegrityError(
                "observation ledger metadata identity differs"
            )
        _digest(genesis_nonce, "genesis nonce")
        expected_instance = _domain_hash(
            _INSTANCE_DOMAIN,
            bytes.fromhex(genesis_nonce),
        )
        if expected_instance != ledger_instance_id:
            raise ObservationLedgerIntegrityError(
                "observation ledger genesis identity differs"
            )
        created = _utc(created_at_utc, "ledger creation time")

        receipt_rows = connection.execute(
            """
            SELECT sequence, event_type, receipt_sha256,
                   previous_receipt_sha256, session_id,
                   host_recorded_at_utc, host_monotonic_ns,
                   process_token, observation_id, observation_sha256,
                   source_observed_at, content_json
              FROM ledger_receipt
             ORDER BY sequence
            """
        ).fetchall()
        if not receipt_rows:
            raise ObservationLedgerIntegrityError(
                "observation ledger has no genesis receipt"
            )
        receipts: list[ObservationLedgerReceipt] = []
        previous = GENESIS_PREVIOUS_RECEIPT
        previous_host_time: datetime | None = None
        monotonic_by_process: dict[str, int] = {}
        sessions: dict[str, str] = {}
        observed_sessions: set[str] = set()
        observation_hashes: set[str] = set()
        for expected_sequence, row in enumerate(receipt_rows, start=1):
            (
                sequence,
                event_type,
                receipt_sha256,
                previous_receipt_sha256,
                session_id,
                host_recorded_at_utc,
                host_monotonic_ns,
                process_token,
                observation_id,
                observation_sha256,
                source_observed_at,
                content_json,
            ) = row
            if sequence != expected_sequence:
                raise ObservationLedgerIntegrityError(
                    "observation ledger sequence is not contiguous"
                )
            try:
                document = json.loads(content_json)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ObservationLedgerIntegrityError(
                    "observation ledger receipt JSON is invalid"
                ) from exc
            if (
                not isinstance(document, dict)
                or content_json != _canonical_json(document)
            ):
                raise ObservationLedgerIntegrityError(
                    "observation ledger receipt JSON is not canonical"
                )
            expected_columns = (
                sequence,
                event_type,
                receipt_sha256,
                previous_receipt_sha256,
                session_id,
                host_recorded_at_utc,
                host_monotonic_ns,
                process_token,
                observation_id,
                observation_sha256,
                source_observed_at,
            )
            document_columns = (
                document.get("sequence"),
                document.get("event_type"),
                _receipt_hash(document),
                document.get("previous_receipt_sha256"),
                document.get("session_id"),
                document.get("host_recorded_at_utc"),
                document.get("host_monotonic_ns"),
                document.get("process_token"),
                document.get("observation_id"),
                document.get("observation_sha256"),
                document.get("source_observed_at"),
            )
            if expected_columns != document_columns:
                raise ObservationLedgerIntegrityError(
                    "observation ledger receipt row differs from its content"
                )
            if (
                document.get("schema_version") != RECEIPT_SCHEMA_VERSION
                or document.get("policy_version") != POLICY_VERSION
                or document.get("contract_sha256") != contract_sha256
                or document.get("ledger_instance_id")
                != ledger_instance_id
                or previous_receipt_sha256 != previous
            ):
                raise ObservationLedgerIntegrityError(
                    "observation ledger receipt identity or chain differs"
                )
            _digest(receipt_sha256, "receipt hash")
            _digest(process_token, "receipt process token")
            host_time = _utc(
                host_recorded_at_utc,
                "receipt host-recorded time",
            )
            if (
                previous_host_time is not None
                and host_time < previous_host_time
            ):
                raise ObservationLedgerIntegrityError(
                    "observation ledger host time is non-monotone"
                )
            previous_monotonic = monotonic_by_process.get(process_token)
            if (
                previous_monotonic is not None
                and host_monotonic_ns <= previous_monotonic
            ):
                raise ObservationLedgerIntegrityError(
                    "observation ledger process monotonic witness differs"
                )
            monotonic_by_process[process_token] = host_monotonic_ns

            if event_type == "genesis":
                if (
                    sequence != 1
                    or session_id is not None
                    or document.get("genesis_nonce") != genesis_nonce
                    or document.get("fixture_policy_sha256")
                    != policy_sha256
                    or host_time != created
                    or any(
                        value is not None
                        for value in (
                            observation_id,
                            observation_sha256,
                            source_observed_at,
                        )
                    )
                ):
                    raise ObservationLedgerIntegrityError(
                        "observation ledger genesis receipt differs"
                    )
                expected_keys = {
                    "schema_version",
                    "policy_version",
                    "event_type",
                    "sequence",
                    "previous_receipt_sha256",
                    "contract_sha256",
                    "ledger_instance_id",
                    "session_id",
                    "host_recorded_at_utc",
                    "host_monotonic_ns",
                    "process_token",
                    "genesis_nonce",
                    "fixture_policy_sha256",
                }
            elif event_type == "session_open":
                _digest(session_id, "receipt session ID")
                if (
                    session_id in sessions
                    or any(
                        value is not None
                        for value in (
                            observation_id,
                            observation_sha256,
                            source_observed_at,
                        )
                    )
                ):
                    raise ObservationLedgerIntegrityError(
                        "observation ledger session-open grammar differs"
                    )
                sessions[session_id] = receipt_sha256
                expected_keys = {
                    "schema_version",
                    "policy_version",
                    "event_type",
                    "sequence",
                    "previous_receipt_sha256",
                    "contract_sha256",
                    "ledger_instance_id",
                    "session_id",
                    "host_recorded_at_utc",
                    "host_monotonic_ns",
                    "process_token",
                }
            elif event_type == "observation_recorded":
                _digest(session_id, "observation session ID")
                _digest(
                    observation_sha256,
                    "observation content hash",
                )
                if (
                    session_id not in sessions
                    or session_id in observed_sessions
                    or not isinstance(observation_id, str)
                    or not observation_id
                    or observation_sha256 in observation_hashes
                    or not isinstance(source_observed_at, str)
                ):
                    raise ObservationLedgerIntegrityError(
                        "observation ledger observation grammar differs"
                    )
                _utc(
                    source_observed_at,
                    "untrusted source observation time",
                )
                observed_sessions.add(session_id)
                observation_hashes.add(observation_sha256)
                expected_keys = {
                    "schema_version",
                    "policy_version",
                    "event_type",
                    "sequence",
                    "previous_receipt_sha256",
                    "contract_sha256",
                    "ledger_instance_id",
                    "session_id",
                    "host_recorded_at_utc",
                    "host_monotonic_ns",
                    "process_token",
                    "observation_id",
                    "observation_sha256",
                    "source_observed_at",
                }
            else:
                raise ObservationLedgerIntegrityError(
                    "observation ledger receipt event type differs"
                )
            if set(document) != expected_keys:
                raise ObservationLedgerIntegrityError(
                    "observation ledger receipt fields differ"
                )
            receipts.append(
                ObservationLedgerReceipt(receipt_sha256, document)
            )
            previous = receipt_sha256
            previous_host_time = host_time

        if receipts[0].receipt_sha256 != genesis_receipt_sha256:
            raise ObservationLedgerIntegrityError(
                "observation ledger genesis receipt identity differs"
            )
        trigger_names = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                  FROM sqlite_master
                 WHERE type = 'trigger'
                """
            ).fetchall()
        }
        if trigger_names != {
            "ledger_metadata_no_update",
            "ledger_metadata_no_delete",
            "ledger_receipt_no_update",
            "ledger_receipt_no_delete",
        }:
            raise ObservationLedgerIntegrityError(
                "observation ledger append-only triggers differ"
            )
        return tuple(receipts)

    @staticmethod
    def _new_connection(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(
            path,
            timeout=SQLITE_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _insert_receipt(
        connection: sqlite3.Connection,
        receipt_sha256: str,
        document: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO ledger_receipt (
                sequence, event_type, receipt_sha256,
                previous_receipt_sha256, session_id,
                host_recorded_at_utc, host_monotonic_ns,
                process_token, observation_id, observation_sha256,
                source_observed_at, content_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document["sequence"],
                document["event_type"],
                receipt_sha256,
                document["previous_receipt_sha256"],
                document["session_id"],
                document["host_recorded_at_utc"],
                document["host_monotonic_ns"],
                document["process_token"],
                document.get("observation_id"),
                document.get("observation_sha256"),
                document.get("source_observed_at"),
                _canonical_json(document),
            ),
        )

    @staticmethod
    def _remove_failed_database(path: Path) -> None:
        for candidate in (
            path,
            Path(f"{path}-wal"),
            Path(f"{path}-shm"),
        ):
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
