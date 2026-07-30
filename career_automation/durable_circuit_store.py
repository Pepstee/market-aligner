"""Local-only durable JAA-11 circuit state with fail-closed verification.

This module cannot browse, submit, mint release tokens, handle credentials, or
activate a canary.  It persists only the inert fixture circuit's terminal trip
state and append-only reset proposals.  Reset authority is deliberately
unavailable: no operation can transition a tripped circuit back to armed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from career_automation.official_ats_adapter import (
    AdapterAttemptResult,
    AdapterFixtureObservation,
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
    INVARIANT_BREACHES,
    FixtureAdapterContract,
    FixtureAdapterEvidence,
    compile_fixture_evidence,
    evaluate_fixture_observation,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
STORE_SCHEMA_VERSION = "jaa11.durable-circuit-store.v1"
RECEIPT_SCHEMA_VERSION = "jaa11.durable-circuit-receipt.v1"
POLICY_VERSION = "jaa11.durable-trip-only-policy.v2"
RESET_AUTHORITY_ANCHOR = "unavailable_local_only_fail_closed"
GENESIS_LINK = "genesis"
SQLITE_TIMEOUT_SECONDS = 10.0


class CircuitStoreError(RuntimeError):
    """Base error for the local durable circuit contract."""


class CircuitIntegrityError(CircuitStoreError):
    """The durable state cannot be trusted and must be treated as tripped."""


class CircuitStateError(CircuitStoreError):
    """A requested transition is not legal for the verified state."""


class StaleCircuitVersionError(CircuitStateError):
    """The caller attempted to extend an obsolete circuit version."""


@dataclass(frozen=True)
class CircuitStoreIdentity:
    adapter_contract_sha256: str
    circuit_instance_id: str
    genesis_receipt_sha256: str

    def __post_init__(self) -> None:
        _digest(self.adapter_contract_sha256, "adapter contract hash")
        _instance_id(self.circuit_instance_id)
        _digest(self.genesis_receipt_sha256, "genesis receipt hash")

    def document(self) -> dict[str, str]:
        return {
            "adapter_contract_sha256": self.adapter_contract_sha256,
            "circuit_instance_id": self.circuit_instance_id,
            "genesis_receipt_sha256": self.genesis_receipt_sha256,
        }


@dataclass(frozen=True)
class CircuitSnapshot:
    state: str
    version: int
    receipt_sequence: int
    head_receipt_sha256: str
    breach_code: str | None

    def __post_init__(self) -> None:
        if self.state not in {"armed", "tripped"}:
            raise CircuitIntegrityError("durable circuit state is invalid")
        if not isinstance(self.version, int) or self.version < 0:
            raise CircuitIntegrityError("durable circuit version is invalid")
        if (
            not isinstance(self.receipt_sequence, int)
            or self.receipt_sequence < 0
        ):
            raise CircuitIntegrityError(
                "durable circuit receipt sequence is invalid"
            )
        _digest(self.head_receipt_sha256, "head receipt hash")
        if self.state == "armed" and self.breach_code is not None:
            raise CircuitIntegrityError(
                "armed durable circuit cannot retain a breach"
            )
        if (
            self.state == "tripped"
            and self.breach_code not in INVARIANT_BREACHES
        ):
            raise CircuitIntegrityError(
                "tripped durable circuit requires a known breach"
            )


@dataclass(frozen=True)
class DurableCircuitReceipt:
    receipt_sha256: str
    document: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.receipt_sha256, "receipt hash")
        if _content_hash(dict(self.document)) != self.receipt_sha256:
            raise CircuitIntegrityError(
                "durable circuit receipt content hash differs"
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


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _instance_id(value: str) -> str:
    if not isinstance(value, str) or not INSTANCE_ID.fullmatch(value):
        raise ValueError("circuit instance ID is invalid")
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
            "durable circuit store requires a filesystem SQLite path"
        )
    path = Path(raw).expanduser().resolve(strict=False)
    if must_exist and not path.is_file():
        raise CircuitIntegrityError(
            "durable circuit database is missing or replaced"
        )
    if not must_exist and path.exists():
        raise FileExistsError(
            "durable circuit database must not already exist"
        )
    return path


def circuit_policy_document() -> dict[str, object]:
    """Return the immutable, non-authorizing local store policy."""
    return {
        "schema_version": STORE_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "states": ["armed", "tripped"],
        "terminal_state": "tripped",
        "reset_mutation": "withheld",
        "reset_authority_anchor": RESET_AUTHORITY_ANCHOR,
        "external_action_capability": False,
        "fixture_scope_only": True,
        "whole_file_replacement_limit": (
            "detectable_only_with_pinned_instance_and_genesis"
        ),
        "filesystem_privileged_writer_limit": (
            "surgical_partial_rewrite_undetectable_no_local_mitigation"
        ),
    }


def _state_integrity_document(
    identity: CircuitStoreIdentity,
    snapshot: CircuitSnapshot,
) -> dict[str, object]:
    return {
        "schema_version": STORE_SCHEMA_VERSION,
        **identity.document(),
        "state": snapshot.state,
        "version": snapshot.version,
        "receipt_sequence": snapshot.receipt_sequence,
        "head_receipt_sha256": snapshot.head_receipt_sha256,
        "breach_code": snapshot.breach_code,
    }


def _receipt(
    *,
    identity_without_genesis: tuple[str, str],
    event_type: str,
    sequence: int,
    previous_receipt_sha256: str,
    prior_state: str | None,
    prior_version: int,
    next_state: str,
    next_version: int,
    breach_code: str | None = None,
    initialization_nonce: str | None = None,
    reset_proposal_id: str | None = None,
    reset_rationale_sha256: str | None = None,
) -> DurableCircuitReceipt:
    adapter_contract_sha256, circuit_instance_id = (
        identity_without_genesis
    )
    document: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "event_type": event_type,
        "adapter_contract_sha256": adapter_contract_sha256,
        "circuit_instance_id": circuit_instance_id,
        "sequence": sequence,
        "previous_receipt_sha256": previous_receipt_sha256,
        "prior_state": prior_state,
        "prior_version": prior_version,
        "next_state": next_state,
        "next_version": next_version,
        "breach_code": breach_code,
        "initialization_nonce": initialization_nonce,
        "reset_proposal_id": reset_proposal_id,
        "reset_rationale_sha256": reset_rationale_sha256,
        "reset_authority_anchor": RESET_AUTHORITY_ANCHOR,
        "reset_mutation_performed": False,
    }
    receipt_sha256 = _content_hash(document)
    return DurableCircuitReceipt(receipt_sha256, document)


class DurableCircuitStore:
    """Pinned, process-independent, terminal-trip circuit store."""

    def __init__(
        self,
        database_path: Path,
        identity: CircuitStoreIdentity,
    ) -> None:
        self._database_path = database_path
        self.identity = identity

    @property
    def database_path(self) -> Path:
        return self._database_path

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        *,
        adapter_contract_sha256: str,
        circuit_instance_id: str,
    ) -> DurableCircuitStore:
        path = _database_path(database_path, must_exist=False)
        expected_contract = (
            FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256
        )
        if adapter_contract_sha256 != expected_contract:
            raise ValueError(
                "fixture durable circuit requires the canonical contract"
            )
        _digest(adapter_contract_sha256, "adapter contract hash")
        _instance_id(circuit_instance_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(32).hex()
        genesis = _receipt(
            identity_without_genesis=(
                adapter_contract_sha256,
                circuit_instance_id,
            ),
            event_type="initialize",
            sequence=0,
            previous_receipt_sha256=GENESIS_LINK,
            prior_state=None,
            prior_version=-1,
            next_state="armed",
            next_version=0,
            initialization_nonce=nonce,
        )
        identity = CircuitStoreIdentity(
            adapter_contract_sha256,
            circuit_instance_id,
            genesis.receipt_sha256,
        )
        snapshot = CircuitSnapshot(
            state="armed",
            version=0,
            receipt_sequence=0,
            head_receipt_sha256=genesis.receipt_sha256,
            breach_code=None,
        )
        connection = cls._new_connection(path)
        try:
            connection.executescript(
                """
                CREATE TABLE circuit_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    policy_json TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL
                );
                CREATE TABLE circuit_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    adapter_contract_sha256 TEXT NOT NULL,
                    circuit_instance_id TEXT NOT NULL,
                    genesis_receipt_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('armed', 'tripped')),
                    version INTEGER NOT NULL CHECK (version >= 0),
                    receipt_sequence INTEGER NOT NULL
                        CHECK (receipt_sequence >= 0),
                    head_receipt_sha256 TEXT NOT NULL,
                    breach_code TEXT,
                    state_integrity_sha256 TEXT NOT NULL
                );
                CREATE TABLE circuit_receipt (
                    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
                    event_type TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    previous_receipt_sha256 TEXT NOT NULL,
                    reset_proposal_id TEXT UNIQUE,
                    content_json TEXT NOT NULL
                );
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            policy = circuit_policy_document()
            policy_json = _canonical_json(policy)
            connection.execute(
                """
                INSERT INTO circuit_metadata (
                    singleton, schema_version, policy_json, policy_sha256
                ) VALUES (1, ?, ?, ?)
                """,
                (
                    STORE_SCHEMA_VERSION,
                    policy_json,
                    _content_hash(policy),
                ),
            )
            connection.execute(
                """
                INSERT INTO circuit_receipt (
                    sequence, event_type, receipt_sha256,
                    previous_receipt_sha256, reset_proposal_id, content_json
                ) VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (
                    0,
                    "initialize",
                    genesis.receipt_sha256,
                    GENESIS_LINK,
                    _canonical_json(dict(genesis.document)),
                ),
            )
            connection.execute(
                """
                INSERT INTO circuit_state (
                    singleton, adapter_contract_sha256,
                    circuit_instance_id, genesis_receipt_sha256,
                    state, version, receipt_sequence,
                    head_receipt_sha256, breach_code,
                    state_integrity_sha256
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identity.adapter_contract_sha256,
                    identity.circuit_instance_id,
                    identity.genesis_receipt_sha256,
                    snapshot.state,
                    snapshot.version,
                    snapshot.receipt_sequence,
                    snapshot.head_receipt_sha256,
                    snapshot.breach_code,
                    _content_hash(
                        _state_integrity_document(identity, snapshot)
                    ),
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            connection.close()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
        finally:
            if connection:
                connection.close()
        store = cls(path, identity)
        store.verify()
        return store

    @classmethod
    def open(
        cls,
        database_path: str | Path,
        *,
        identity: CircuitStoreIdentity,
    ) -> DurableCircuitStore:
        if not isinstance(identity, CircuitStoreIdentity):
            raise TypeError("durable circuit open requires a pinned identity")
        path = _database_path(database_path, must_exist=True)
        store = cls(path, identity)
        store.verify()
        return store

    @staticmethod
    def _new_connection(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(
            path,
            timeout=SQLITE_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            f"PRAGMA busy_timeout = {int(SQLITE_TIMEOUT_SECONDS * 1000)}"
        )
        return connection

    def _connect(self) -> sqlite3.Connection:
        _database_path(self._database_path, must_exist=True)
        return self._new_connection(self._database_path)

    def verify(self) -> CircuitSnapshot:
        connection = self._connect()
        try:
            return self._verify_connection(connection)
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            raise CircuitIntegrityError(
                "durable circuit verification failed closed"
            ) from exc
        finally:
            connection.close()

    def receipts(self) -> tuple[DurableCircuitReceipt, ...]:
        connection = self._connect()
        try:
            self._verify_connection(connection)
            rows = connection.execute(
                "SELECT receipt_sha256, content_json "
                "FROM circuit_receipt ORDER BY sequence"
            ).fetchall()
            return tuple(
                DurableCircuitReceipt(
                    row["receipt_sha256"],
                    json.loads(row["content_json"]),
                )
                for row in rows
            )
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            raise CircuitIntegrityError(
                "durable circuit receipt read failed closed"
            ) from exc
        finally:
            connection.close()

    def require_armed(self) -> CircuitSnapshot:
        snapshot = self.verify()
        if snapshot.state != "armed":
            raise CircuitStateError("durable circuit is tripped")
        return snapshot

    def trip(
        self,
        *,
        expected_version: int,
        breach_code: str,
    ) -> DurableCircuitReceipt:
        if breach_code not in INVARIANT_BREACHES:
            raise ValueError("durable circuit breach code is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._verify_connection(connection)
            if snapshot.state != "armed":
                raise CircuitStateError(
                    "durable circuit trip is already recorded"
                )
            if expected_version != snapshot.version:
                raise StaleCircuitVersionError(
                    "durable circuit expected version is stale"
                )
            receipt = _receipt(
                identity_without_genesis=(
                    self.identity.adapter_contract_sha256,
                    self.identity.circuit_instance_id,
                ),
                event_type="trip",
                sequence=snapshot.receipt_sequence + 1,
                previous_receipt_sha256=(
                    snapshot.head_receipt_sha256
                ),
                prior_state=snapshot.state,
                prior_version=snapshot.version,
                next_state="tripped",
                next_version=snapshot.version + 1,
                breach_code=breach_code,
            )
            self._append_receipt(connection, receipt)
            next_snapshot = CircuitSnapshot(
                state="tripped",
                version=snapshot.version + 1,
                receipt_sequence=snapshot.receipt_sequence + 1,
                head_receipt_sha256=receipt.receipt_sha256,
                breach_code=breach_code,
            )
            self._write_snapshot(
                connection,
                snapshot,
                next_snapshot,
            )
            verified = self._verify_connection(connection)
            if verified != next_snapshot:
                raise CircuitIntegrityError(
                    "durable circuit trip did not verify"
                )
            connection.commit()
            return receipt
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def propose_reset(
        self,
        *,
        expected_version: int,
        reset_proposal_id: str,
        rationale_sha256: str,
    ) -> DurableCircuitReceipt:
        _digest(reset_proposal_id, "reset proposal ID")
        _digest(rationale_sha256, "reset rationale hash")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._verify_connection(connection)
            if snapshot.state != "tripped":
                raise CircuitStateError(
                    "reset proposal requires a tripped circuit"
                )
            if expected_version != snapshot.version:
                raise StaleCircuitVersionError(
                    "durable circuit expected version is stale"
                )
            if connection.execute(
                "SELECT 1 FROM circuit_receipt "
                "WHERE reset_proposal_id = ?",
                (reset_proposal_id,),
            ).fetchone():
                raise CircuitStateError(
                    "reset proposal replay is not permitted"
                )
            receipt = _receipt(
                identity_without_genesis=(
                    self.identity.adapter_contract_sha256,
                    self.identity.circuit_instance_id,
                ),
                event_type="reset_proposal",
                sequence=snapshot.receipt_sequence + 1,
                previous_receipt_sha256=(
                    snapshot.head_receipt_sha256
                ),
                prior_state=snapshot.state,
                prior_version=snapshot.version,
                next_state=snapshot.state,
                next_version=snapshot.version,
                reset_proposal_id=reset_proposal_id,
                reset_rationale_sha256=rationale_sha256,
            )
            self._append_receipt(connection, receipt)
            next_snapshot = CircuitSnapshot(
                state=snapshot.state,
                version=snapshot.version,
                receipt_sequence=snapshot.receipt_sequence + 1,
                head_receipt_sha256=receipt.receipt_sha256,
                breach_code=snapshot.breach_code,
            )
            self._write_snapshot(
                connection,
                snapshot,
                next_snapshot,
            )
            verified = self._verify_connection(connection)
            if verified != next_snapshot:
                raise CircuitIntegrityError(
                    "durable reset proposal did not verify"
                )
            connection.commit()
            return receipt
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _append_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: DurableCircuitReceipt,
    ) -> None:
        document = dict(receipt.document)
        connection.execute(
            """
            INSERT INTO circuit_receipt (
                sequence, event_type, receipt_sha256,
                previous_receipt_sha256, reset_proposal_id, content_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                document["sequence"],
                document["event_type"],
                receipt.receipt_sha256,
                document["previous_receipt_sha256"],
                document["reset_proposal_id"],
                _canonical_json(document),
            ),
        )

    def _write_snapshot(
        self,
        connection: sqlite3.Connection,
        prior: CircuitSnapshot,
        next_snapshot: CircuitSnapshot,
    ) -> None:
        integrity_sha256 = _content_hash(
            _state_integrity_document(self.identity, next_snapshot)
        )
        cursor = connection.execute(
            """
            UPDATE circuit_state
            SET state = ?, version = ?, receipt_sequence = ?,
                head_receipt_sha256 = ?, breach_code = ?,
                state_integrity_sha256 = ?
            WHERE singleton = 1
              AND state = ?
              AND version = ?
              AND receipt_sequence = ?
              AND head_receipt_sha256 = ?
            """,
            (
                next_snapshot.state,
                next_snapshot.version,
                next_snapshot.receipt_sequence,
                next_snapshot.head_receipt_sha256,
                next_snapshot.breach_code,
                integrity_sha256,
                prior.state,
                prior.version,
                prior.receipt_sequence,
                prior.head_receipt_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise StaleCircuitVersionError(
                "durable circuit compare-and-set failed"
            )

    def _verify_connection(
        self,
        connection: sqlite3.Connection,
    ) -> CircuitSnapshot:
        metadata = connection.execute(
            "SELECT * FROM circuit_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise CircuitIntegrityError(
                "durable circuit metadata is missing"
            )
        policy = circuit_policy_document()
        policy_json = _canonical_json(policy)
        if (
            metadata["schema_version"] != STORE_SCHEMA_VERSION
            or metadata["policy_json"] != policy_json
            or metadata["policy_sha256"] != _content_hash(policy)
        ):
            raise CircuitIntegrityError(
                "durable circuit policy differs from the local contract"
            )

        state = connection.execute(
            "SELECT * FROM circuit_state WHERE singleton = 1"
        ).fetchone()
        if state is None:
            raise CircuitIntegrityError("durable circuit state is missing")
        if (
            state["adapter_contract_sha256"]
            != self.identity.adapter_contract_sha256
            or state["circuit_instance_id"]
            != self.identity.circuit_instance_id
            or state["genesis_receipt_sha256"]
            != self.identity.genesis_receipt_sha256
        ):
            raise CircuitIntegrityError(
                "durable circuit database differs from pinned identity"
            )
        snapshot = CircuitSnapshot(
            state=state["state"],
            version=state["version"],
            receipt_sequence=state["receipt_sequence"],
            head_receipt_sha256=state["head_receipt_sha256"],
            breach_code=state["breach_code"],
        )
        if state["state_integrity_sha256"] != _content_hash(
            _state_integrity_document(self.identity, snapshot)
        ):
            raise CircuitIntegrityError(
                "durable circuit state integrity differs"
            )
        self._verify_receipt_chain(connection, snapshot)
        return snapshot

    def _verify_receipt_chain(
        self,
        connection: sqlite3.Connection,
        snapshot: CircuitSnapshot,
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM circuit_receipt ORDER BY sequence"
        ).fetchall()
        if (
            len(rows) != snapshot.receipt_sequence + 1
            or not rows
        ):
            raise CircuitIntegrityError(
                "durable circuit receipt sequence has gaps"
            )
        expected_state: str | None = None
        expected_version = -1
        expected_previous = GENESIS_LINK
        breach_code: str | None = None
        for expected_sequence, row in enumerate(rows):
            document = json.loads(row["content_json"])
            if not isinstance(document, dict):
                raise CircuitIntegrityError(
                    "durable circuit receipt is not an object"
                )
            receipt = DurableCircuitReceipt(
                row["receipt_sha256"],
                document,
            )
            if (
                row["sequence"] != expected_sequence
                or document.get("sequence") != expected_sequence
                or row["event_type"] != document.get("event_type")
                or row["previous_receipt_sha256"]
                != document.get("previous_receipt_sha256")
                or row["reset_proposal_id"]
                != document.get("reset_proposal_id")
                or row["content_json"] != _canonical_json(document)
                or document.get("schema_version")
                != RECEIPT_SCHEMA_VERSION
                or document.get("policy_version") != POLICY_VERSION
                or document.get("adapter_contract_sha256")
                != self.identity.adapter_contract_sha256
                or document.get("circuit_instance_id")
                != self.identity.circuit_instance_id
                or document.get("previous_receipt_sha256")
                != expected_previous
                or document.get("prior_state") != expected_state
                or document.get("prior_version") != expected_version
                or document.get("reset_authority_anchor")
                != RESET_AUTHORITY_ANCHOR
                or document.get("reset_mutation_performed") is not False
            ):
                raise CircuitIntegrityError(
                    "durable circuit receipt chain differs"
                )
            event_type = document.get("event_type")
            if event_type == "initialize":
                if (
                    expected_sequence != 0
                    or document.get("next_state") != "armed"
                    or document.get("next_version") != 0
                    or document.get("breach_code") is not None
                    or not HEX_64.fullmatch(
                        document.get("initialization_nonce", "")
                    )
                    or any(
                        document.get(key) is not None
                        for key in (
                            "reset_proposal_id",
                            "reset_rationale_sha256",
                        )
                    )
                    or receipt.receipt_sha256
                    != self.identity.genesis_receipt_sha256
                ):
                    raise CircuitIntegrityError(
                        "durable circuit genesis receipt differs"
                    )
                expected_state = "armed"
                expected_version = 0
            elif event_type == "trip":
                reason = document.get("breach_code")
                if (
                    expected_state != "armed"
                    or reason not in INVARIANT_BREACHES
                    or document.get("next_state") != "tripped"
                    or document.get("next_version")
                    != expected_version + 1
                    or document.get("initialization_nonce") is not None
                    or document.get("reset_proposal_id") is not None
                    or document.get("reset_rationale_sha256") is not None
                ):
                    raise CircuitIntegrityError(
                        "durable circuit trip receipt differs"
                    )
                expected_state = "tripped"
                expected_version += 1
                breach_code = reason
            elif event_type == "reset_proposal":
                if (
                    expected_state != "tripped"
                    or document.get("next_state") != expected_state
                    or document.get("next_version") != expected_version
                    or document.get("breach_code") is not None
                    or document.get("initialization_nonce") is not None
                    or not HEX_64.fullmatch(
                        document.get("reset_proposal_id", "")
                    )
                    or not HEX_64.fullmatch(
                        document.get("reset_rationale_sha256", "")
                    )
                ):
                    raise CircuitIntegrityError(
                        "durable reset proposal receipt differs"
                    )
            else:
                raise CircuitIntegrityError(
                    "durable circuit receipt event is unsupported"
                )
            expected_previous = receipt.receipt_sha256
        if (
            expected_state != snapshot.state
            or expected_version != snapshot.version
            or expected_previous != snapshot.head_receipt_sha256
            or breach_code != snapshot.breach_code
        ):
            raise CircuitIntegrityError(
                "durable circuit state differs from receipt chain"
            )


def assess_fixture_adapter_attempt(
    contract: FixtureAdapterContract,
    store: DurableCircuitStore,
    observation: AdapterFixtureObservation,
) -> tuple[
    AdapterAttemptResult,
    FixtureAdapterEvidence | None,
    DurableCircuitReceipt | None,
]:
    """Assess inert fixture evidence through the pinned durable circuit."""
    if contract != FROZEN_FIXTURE_ADAPTER_CONTRACT:
        raise ValueError(
            "fixture assessment requires the canonical adapter contract"
        )
    if type(store) is not DurableCircuitStore:
        raise TypeError(
            "fixture assessment requires an exact DurableCircuitStore"
        )
    if not isinstance(observation, AdapterFixtureObservation):
        raise TypeError(
            "fixture assessment requires an AdapterFixtureObservation"
        )
    if observation.adapter_contract_sha256 != contract.contract_sha256:
        raise ValueError("fixture observation binds a different contract")
    if (
        store.identity.adapter_contract_sha256
        != contract.contract_sha256
    ):
        raise ValueError("durable circuit binds a different contract")

    initial = store.require_armed()
    evaluation = evaluate_fixture_observation(contract, observation)
    if evaluation.outcome == "breach":
        breach = evaluation.reason_codes[0]
        trip_receipt = store.trip(
            expected_version=initial.version,
            breach_code=breach,
        )
        result = AdapterAttemptResult(
            outcome="circuit_open",
            reason_codes=(breach,),
            evidence_id=None,
            receipt_id=None,
            halts_canaries=True,
        )
        return result, None, trip_receipt

    confirmed = store.verify()
    if confirmed != initial or confirmed.state != "armed":
        raise CircuitStateError(
            "durable circuit changed during fixture assessment"
        )
    if evaluation.outcome == "parked":
        result = AdapterAttemptResult(
            outcome="parked",
            reason_codes=evaluation.reason_codes,
            evidence_id=None,
            receipt_id=None,
            halts_canaries=False,
        )
        return result, None, None
    if evaluation.outcome != "pass_candidate":
        raise CircuitIntegrityError(
            "fixture evaluation produced an unsupported outcome"
        )

    evidence = compile_fixture_evidence(contract, observation)
    result = AdapterAttemptResult(
        outcome="fixture_pass",
        reason_codes=(),
        evidence_id=evidence.evidence_id,
        receipt_id=evidence.receipt_id,
        halts_canaries=False,
    )
    return result, evidence, None
