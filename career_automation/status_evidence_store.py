"""Durable local-only evidence storage for the JAA-12 status contract.

The store preserves exact local-export bytes, verified status observations,
complete timelines, and non-sendable follow-up intents.  It has no connector,
browser, network, credential, or external-action capability.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from career_automation.lifecycle import LEGAL_TRANSITIONS
from career_automation.models import PipelineState
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    TERMINAL_STATUS_STATES,
    CensoredSilence,
    FollowUpIntent,
    RawStatusEvidence,
    StatusObservation,
    StatusTimeline,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
STORE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
STORE_SCHEMA_VERSION = "jaa12.status-evidence-store.v1"
RECEIPT_SCHEMA_VERSION = "jaa12.status-evidence-store-receipt.v1"
POLICY_VERSION = "jaa12.durable-local-evidence-policy.v1"
GENESIS_LINK = "genesis"
SQLITE_TIMEOUT_SECONDS = 10.0


class StatusEvidenceStoreError(RuntimeError):
    """Base error for the durable local status-evidence boundary."""


class StatusEvidenceIntegrityError(StatusEvidenceStoreError):
    """Stored evidence failed closed verification."""


class StatusEvidenceStateError(StatusEvidenceStoreError):
    """A requested append is not legal for the durable state."""


class StatusEvidenceConflictError(StatusEvidenceStateError):
    """An immutable durable identity was reused with different content."""


@dataclass(frozen=True)
class StatusEvidenceStoreIdentity:
    contract_sha256: str
    store_instance_id: str
    genesis_receipt_sha256: str

    def __post_init__(self) -> None:
        _digest(self.contract_sha256, "status contract hash")
        _store_id(self.store_instance_id)
        _digest(self.genesis_receipt_sha256, "genesis receipt hash")
        if (
            self.contract_sha256
            != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
        ):
            raise ValueError(
                "status evidence store requires the canonical contract"
            )

    def document(self) -> dict[str, str]:
        return {
            "contract_sha256": self.contract_sha256,
            "store_instance_id": self.store_instance_id,
            "genesis_receipt_sha256": self.genesis_receipt_sha256,
        }


@dataclass(frozen=True)
class StatusEvidenceStoreSnapshot:
    receipt_sequence: int
    head_receipt_sha256: str
    raw_blob_count: int
    raw_evidence_count: int
    observation_count: int
    timeline_count: int
    intent_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_sequence, int) or self.receipt_sequence < 0:
            raise StatusEvidenceIntegrityError(
                "status evidence receipt sequence is invalid"
            )
        _digest(self.head_receipt_sha256, "status evidence head receipt")
        for value in (
            self.raw_blob_count,
            self.raw_evidence_count,
            self.observation_count,
            self.timeline_count,
            self.intent_count,
        ):
            if not isinstance(value, int) or value < 0:
                raise StatusEvidenceIntegrityError(
                    "status evidence durable count is invalid"
                )


@dataclass(frozen=True)
class StatusEvidenceStreamState:
    observation_count: int
    last_observed_at: str
    current_state: PipelineState
    terminal_state: PipelineState | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.observation_count, int)
            or self.observation_count <= 0
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence stream count is invalid"
            )
        if not isinstance(self.current_state, PipelineState):
            raise StatusEvidenceIntegrityError(
                "status evidence current state is invalid"
            )
        if (
            self.terminal_state is not None
            and (
                not isinstance(self.terminal_state, PipelineState)
                or self.terminal_state not in TERMINAL_STATUS_STATES
                or self.current_state is not self.terminal_state
            )
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence terminal state is invalid"
            )
        try:
            _parsed_datetime(self.last_observed_at)
        except (TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "status evidence stream time is invalid"
            ) from exc


@dataclass(frozen=True)
class StatusEvidenceStoreReceipt:
    receipt_sha256: str
    document: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.receipt_sha256, "status evidence receipt hash")
        if _content_hash(dict(self.document)) != self.receipt_sha256:
            raise StatusEvidenceIntegrityError(
                "status evidence receipt differs from exact content"
            )


@dataclass(frozen=True)
class StatusEvidenceStorePolicy:
    contract_sha256: str
    connector_authority: str = "withheld"
    mailbox_access: str = "withheld"
    portal_access: str = "withheld"
    message_send_authority: str = "withheld"
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    external_action_capability: bool = False
    schema_version: str = STORE_SCHEMA_VERSION
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        _digest(self.contract_sha256, "status store policy contract hash")
        if (
            self.contract_sha256
            != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
            or self.connector_authority != "withheld"
            or self.mailbox_access != "withheld"
            or self.portal_access != "withheld"
            or self.message_send_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.external_action_capability is not False
            or self.schema_version != STORE_SCHEMA_VERSION
            or self.policy_version != POLICY_VERSION
        ):
            raise ValueError(
                "status evidence policy cannot connect, send, or certify"
            )

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "contract_sha256": self.contract_sha256,
            "raw_export_archive": "content_addressed_exact_bytes",
            "raw_content_trust": "untrusted_data_only",
            "observation_order": "strictly_monotonic_per_application",
            "timeline_registration": "exact_full_observation_prefix",
            "intent_registration": "first_identity_wins",
            "intent_dispatch_state": "unrepresentable",
            "connector_authority": "withheld",
            "mailbox_access": "withheld",
            "portal_access": "withheld",
            "message_send_authority": "withheld",
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
            "external_action_capability": False,
            "whole_file_replacement_limit": (
                "detectable_only_with_pinned_instance_and_genesis"
            ),
            "filesystem_privileged_writer_limit": (
                "surgical_rewrite_undetectable_without_external_authentication"
            ),
        }


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _store_id(value: str) -> str:
    if not isinstance(value, str) or not STORE_ID.fullmatch(value):
        raise ValueError("status evidence store instance ID is invalid")
    return value


FROZEN_STATUS_EVIDENCE_STORE_POLICY = StatusEvidenceStorePolicy(
    contract_sha256=FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256,
)


def _database_path(value: str | Path, *, must_exist: bool) -> Path:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or raw == ":memory:"
        or raw.startswith("file:")
        or "\x00" in raw
    ):
        raise ValueError(
            "status evidence store requires a filesystem SQLite path"
        )
    path = Path(raw).expanduser().resolve(strict=False)
    if must_exist and not path.is_file():
        raise StatusEvidenceIntegrityError(
            "status evidence database is missing or replaced"
        )
    if not must_exist and path.exists():
        raise FileExistsError(
            "status evidence database must not already exist"
        )
    return path


def status_evidence_store_policy() -> dict[str, object]:
    """Return the immutable, non-authorizing durable-store policy."""
    return FROZEN_STATUS_EVIDENCE_STORE_POLICY.document()


def _state_document(
    identity: StatusEvidenceStoreIdentity,
    snapshot: StatusEvidenceStoreSnapshot,
) -> dict[str, object]:
    return {
        "schema_version": STORE_SCHEMA_VERSION,
        **identity.document(),
        "receipt_sequence": snapshot.receipt_sequence,
        "head_receipt_sha256": snapshot.head_receipt_sha256,
        "raw_blob_count": snapshot.raw_blob_count,
        "raw_evidence_count": snapshot.raw_evidence_count,
        "observation_count": snapshot.observation_count,
        "timeline_count": snapshot.timeline_count,
        "intent_count": snapshot.intent_count,
    }


def _receipt(
    identity_without_genesis: tuple[str, str],
    *,
    event_type: str,
    sequence: int,
    previous_receipt_sha256: str,
    payload: Mapping[str, object],
) -> StatusEvidenceStoreReceipt:
    contract_sha256, store_instance_id = identity_without_genesis
    document = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "event_type": event_type,
        "contract_sha256": contract_sha256,
        "store_instance_id": store_instance_id,
        "sequence": sequence,
        "previous_receipt_sha256": previous_receipt_sha256,
        "payload": dict(payload),
        "connector_authority": "withheld",
        "message_send_authority": "withheld",
        "external_action_performed": False,
    }
    return StatusEvidenceStoreReceipt(_content_hash(document), document)


class StatusEvidenceStore:
    """Pinned, process-independent, append-only local evidence store."""

    def __init__(
        self,
        database_path: Path,
        identity: StatusEvidenceStoreIdentity,
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
        contract_sha256: str,
        store_instance_id: str,
    ) -> StatusEvidenceStore:
        path = _database_path(database_path, must_exist=False)
        if (
            contract_sha256
            != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
        ):
            raise ValueError(
                "status evidence store requires the canonical contract"
            )
        _digest(contract_sha256, "status contract hash")
        _store_id(store_instance_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        genesis = _receipt(
            (contract_sha256, store_instance_id),
            event_type="initialize",
            sequence=0,
            previous_receipt_sha256=GENESIS_LINK,
            payload={
                "initialization_nonce": os.urandom(32).hex(),
                "raw_content_trust": "untrusted_data_only",
                "intent_dispatch_state": "unrepresentable",
            },
        )
        identity = StatusEvidenceStoreIdentity(
            contract_sha256,
            store_instance_id,
            genesis.receipt_sha256,
        )
        snapshot = StatusEvidenceStoreSnapshot(
            receipt_sequence=0,
            head_receipt_sha256=genesis.receipt_sha256,
            raw_blob_count=0,
            raw_evidence_count=0,
            observation_count=0,
            timeline_count=0,
            intent_count=0,
        )
        connection = cls._new_connection(path)
        try:
            connection.executescript(_SCHEMA)
            connection.execute("BEGIN IMMEDIATE")
            policy = status_evidence_store_policy()
            connection.execute(
                """
                INSERT INTO status_store_metadata (
                    singleton, schema_version, policy_json, policy_sha256
                ) VALUES (1, ?, ?, ?)
                """,
                (
                    STORE_SCHEMA_VERSION,
                    _canonical_json(policy),
                    _content_hash(policy),
                ),
            )
            connection.execute(
                """
                INSERT INTO status_store_receipt (
                    sequence, event_type, receipt_sha256,
                    previous_receipt_sha256, content_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    0,
                    "initialize",
                    genesis.receipt_sha256,
                    GENESIS_LINK,
                    _canonical_json(dict(genesis.document)),
                ),
            )
            cls._insert_state(connection, identity, snapshot)
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
            connection.close()
        store = cls(path, identity)
        store.verify()
        return store

    @classmethod
    def open(
        cls,
        database_path: str | Path,
        *,
        identity: StatusEvidenceStoreIdentity,
    ) -> StatusEvidenceStore:
        if not isinstance(identity, StatusEvidenceStoreIdentity):
            raise TypeError(
                "status evidence open requires a pinned identity"
            )
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

    @staticmethod
    def _insert_state(
        connection: sqlite3.Connection,
        identity: StatusEvidenceStoreIdentity,
        snapshot: StatusEvidenceStoreSnapshot,
    ) -> None:
        connection.execute(
            """
            INSERT INTO status_store_state (
                singleton, contract_sha256, store_instance_id,
                genesis_receipt_sha256, receipt_sequence,
                head_receipt_sha256, raw_blob_count,
                raw_evidence_count, observation_count,
                timeline_count, intent_count, state_integrity_sha256
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                identity.contract_sha256,
                identity.store_instance_id,
                identity.genesis_receipt_sha256,
                snapshot.receipt_sequence,
                snapshot.head_receipt_sha256,
                snapshot.raw_blob_count,
                snapshot.raw_evidence_count,
                snapshot.observation_count,
                snapshot.timeline_count,
                snapshot.intent_count,
                _content_hash(_state_document(identity, snapshot)),
            ),
        )

    def _write_state(
        self,
        connection: sqlite3.Connection,
        snapshot: StatusEvidenceStoreSnapshot,
    ) -> None:
        connection.execute(
            """
            UPDATE status_store_state SET
                receipt_sequence = ?,
                head_receipt_sha256 = ?,
                raw_blob_count = ?,
                raw_evidence_count = ?,
                observation_count = ?,
                timeline_count = ?,
                intent_count = ?,
                state_integrity_sha256 = ?
            WHERE singleton = 1
            """,
            (
                snapshot.receipt_sequence,
                snapshot.head_receipt_sha256,
                snapshot.raw_blob_count,
                snapshot.raw_evidence_count,
                snapshot.observation_count,
                snapshot.timeline_count,
                snapshot.intent_count,
                _content_hash(_state_document(self.identity, snapshot)),
            ),
        )

    def verify(self) -> StatusEvidenceStoreSnapshot:
        connection = self._connect()
        try:
            return self._verify_connection(connection)
        except StatusEvidenceIntegrityError:
            raise
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "status evidence verification failed closed"
            ) from exc
        finally:
            connection.close()

    def receipts(self) -> tuple[StatusEvidenceStoreReceipt, ...]:
        connection = self._connect()
        try:
            self._verify_connection(connection)
            rows = connection.execute(
                """
                SELECT receipt_sha256, content_json
                FROM status_store_receipt ORDER BY sequence
                """
            ).fetchall()
            return tuple(
                StatusEvidenceStoreReceipt(
                    row["receipt_sha256"],
                    json.loads(row["content_json"]),
                )
                for row in rows
            )
        except StatusEvidenceIntegrityError:
            raise
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "status evidence receipt read failed closed"
            ) from exc
        finally:
            connection.close()

    def read_observations(
        self,
        application_id: str,
        job_key: str,
    ) -> tuple[StatusObservation, ...]:
        rows = self._verified_read_rows(
            """
            SELECT content_json FROM status_observation
            WHERE application_id = ? AND job_key = ?
            ORDER BY stream_sequence
            """,
            (application_id, job_key),
        )
        return tuple(
            self._observation_from_document(
                self._document(row["content_json"])
            )
            for row in rows
        )

    def read_stream_state(
        self,
        application_id: str,
        job_key: str,
    ) -> StatusEvidenceStreamState | None:
        rows = self._verified_read_rows(
            """
            SELECT observation_count, last_observed_at,
                   current_state, terminal_state
            FROM status_application_stream
            WHERE application_id = ? AND job_key = ?
            """,
            (application_id, job_key),
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise StatusEvidenceIntegrityError(
                "status evidence stream lookup is ambiguous"
            )
        row = rows[0]
        try:
            return StatusEvidenceStreamState(
                observation_count=int(row["observation_count"]),
                last_observed_at=row["last_observed_at"],
                current_state=PipelineState(row["current_state"]),
                terminal_state=(
                    None
                    if row["terminal_state"] is None
                    else PipelineState(row["terminal_state"])
                ),
            )
        except StatusEvidenceIntegrityError:
            raise
        except (TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "status evidence stream reconstruction failed closed"
            ) from exc

    def read_timelines(
        self,
        application_id: str,
        job_key: str,
    ) -> tuple[StatusTimeline, ...]:
        rows = self._verified_read_rows(
            """
            SELECT content_json FROM status_timeline_registration
            WHERE application_id = ? AND job_key = ?
            ORDER BY receipt_sequence
            """,
            (application_id, job_key),
        )
        return tuple(
            self._timeline_from_document(
                self._document(row["content_json"])
            )
            for row in rows
        )

    def read_timeline(self, timeline_id: str) -> StatusTimeline:
        _digest(timeline_id, "status timeline identity")
        rows = self._verified_read_rows(
            """
            SELECT content_json FROM status_timeline_registration
            WHERE timeline_id = ?
            """,
            (timeline_id,),
        )
        if len(rows) != 1:
            raise StatusEvidenceIntegrityError(
                "durable status timeline is absent"
            )
        return self._timeline_from_document(
            self._document(rows[0]["content_json"])
        )

    def read_follow_up_intents(
        self,
        application_id: str,
        job_key: str,
    ) -> tuple[FollowUpIntent, ...]:
        rows = self._verified_read_rows(
            """
            SELECT content_json FROM follow_up_intent_registration
            WHERE application_id = ? AND job_key = ?
            ORDER BY receipt_sequence
            """,
            (application_id, job_key),
        )
        return tuple(
            self._intent_from_document(
                self._document(row["content_json"])
            )
            for row in rows
        )

    def read_follow_up_intent(
        self,
        idempotency_key: str,
    ) -> FollowUpIntent:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("follow-up idempotency key is required")
        rows = self._verified_read_rows(
            """
            SELECT content_json FROM follow_up_intent_registration
            WHERE idempotency_key = ?
            """,
            (idempotency_key,),
        )
        if len(rows) != 1:
            raise StatusEvidenceIntegrityError(
                "durable follow-up intent is absent"
            )
        return self._intent_from_document(
            self._document(rows[0]["content_json"])
        )

    def _verified_read_rows(
        self,
        statement: str,
        parameters: tuple[object, ...],
    ) -> list[sqlite3.Row]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._verify_connection(connection)
            rows = connection.execute(statement, parameters).fetchall()
            connection.rollback()
            return rows
        except StatusEvidenceIntegrityError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            if connection.in_transaction:
                connection.rollback()
            raise StatusEvidenceIntegrityError(
                "durable status read failed closed"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _document(content_json: str) -> dict[str, object]:
        try:
            document = json.loads(content_json)
        except (TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "durable typed content is malformed"
            ) from exc
        if (
            not isinstance(document, dict)
            or _canonical_json(document) != content_json
        ):
            raise StatusEvidenceIntegrityError(
                "durable typed content is not canonical"
            )
        return document

    @staticmethod
    def _raw_evidence_from_document(
        document: Mapping[str, object],
    ) -> RawStatusEvidence:
        try:
            evidence = RawStatusEvidence(
                contract_sha256=document["contract_sha256"],
                application_id=document["application_id"],
                job_key=document["job_key"],
                source_kind=document["source_kind"],
                source_record_id=document["source_record_id"],
                source_sha256=document["source_sha256"],
                parsed_status_code=document["parsed_status_code"],
                observed_at=document["observed_at"],
                evidence_id=document["evidence_id"],
                source_reference_kind=document["source_reference_kind"],
                untrusted_content=document["untrusted_content"],
                instruction_authority=document["instruction_authority"],
                candidate_fact_authority=document["candidate_fact_authority"],
                schema_version=document["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "raw status evidence reconstruction failed closed"
            ) from exc
        if _canonical_json(evidence.document()) != _canonical_json(document):
            raise StatusEvidenceIntegrityError(
                "raw status evidence does not round trip"
            )
        return evidence

    @classmethod
    def _observation_from_document(
        cls,
        document: Mapping[str, object],
    ) -> StatusObservation:
        raw_document = document.get("raw_evidence")
        if not isinstance(raw_document, dict):
            raise StatusEvidenceIntegrityError(
                "status observation raw evidence is malformed"
            )
        try:
            classified = document["classified_state"]
            observation = StatusObservation(
                raw_evidence=cls._raw_evidence_from_document(raw_document),
                application_id=document["application_id"],
                job_key=document["job_key"],
                raw_evidence_id=document["raw_evidence_id"],
                source_sha256=document["source_sha256"],
                source_record_id=document["source_record_id"],
                observed_at=document["observed_at"],
                explicit_status_code=document["explicit_status_code"],
                classified_state=(
                    None
                    if classified is None
                    else PipelineState(classified)
                ),
                confidence_bp=document["confidence_bp"],
                abstained=document["abstained"],
                classifier_policy_sha256=document[
                    "classifier_policy_sha256"
                ],
                observation_id=document["observation_id"],
                instruction_authority=document["instruction_authority"],
                candidate_fact_authority=document["candidate_fact_authority"],
                schema_version=document["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "status observation reconstruction failed closed"
            ) from exc
        if _canonical_json(observation.document()) != _canonical_json(document):
            raise StatusEvidenceIntegrityError(
                "status observation does not round trip"
            )
        return observation

    @staticmethod
    def _silence_from_document(
        document: Mapping[str, object],
    ) -> CensoredSilence:
        try:
            silence = CensoredSilence(
                application_id=document["application_id"],
                job_key=document["job_key"],
                as_of=document["as_of"],
                reason=document["reason"],
                classified_state=(
                    None
                    if document["classified_state"] is None
                    else PipelineState(document["classified_state"])
                ),
                rejection_inferred=document["rejection_inferred"],
                schema_version=document["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "censored silence reconstruction failed closed"
            ) from exc
        if _canonical_json(silence.document()) != _canonical_json(document):
            raise StatusEvidenceIntegrityError(
                "censored silence does not round trip"
            )
        return silence

    @classmethod
    def _timeline_from_document(
        cls,
        document: Mapping[str, object],
    ) -> StatusTimeline:
        observations = document.get("observations")
        silence = document.get("censored_silence")
        transitions = document.get("transitions")
        if (
            not isinstance(observations, list)
            or not all(isinstance(row, dict) for row in observations)
            or not isinstance(silence, list)
            or not all(isinstance(row, dict) for row in silence)
            or not isinstance(transitions, list)
        ):
            raise StatusEvidenceIntegrityError(
                "status timeline typed content is malformed"
            )
        try:
            timeline = StatusTimeline(
                contract_sha256=document["contract_sha256"],
                application_id=document["application_id"],
                job_key=document["job_key"],
                baseline_state=PipelineState(document["baseline_state"]),
                observations=tuple(
                    cls._observation_from_document(row)
                    for row in observations
                ),
                transitions=tuple(tuple(row) for row in transitions),
                censored_silence=tuple(
                    cls._silence_from_document(row) for row in silence
                ),
                final_state=PipelineState(document["final_state"]),
                timeline_id=document["timeline_id"],
                dependency_satisfied=document["dependency_satisfied"],
                connector_evidence=document["connector_evidence"],
                production_certification=document[
                    "production_certification"
                ],
                certifies_slice=document["certifies_slice"],
                schema_version=document["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "status timeline reconstruction failed closed"
            ) from exc
        if _canonical_json(timeline.document()) != _canonical_json(document):
            raise StatusEvidenceIntegrityError(
                "status timeline does not round trip"
            )
        return timeline

    @classmethod
    def _intent_from_document(
        cls,
        document: Mapping[str, object],
    ) -> FollowUpIntent:
        timeline_document = document.get("timeline")
        if not isinstance(timeline_document, dict):
            raise StatusEvidenceIntegrityError(
                "follow-up intent timeline is malformed"
            )
        try:
            intent = FollowUpIntent(
                contract_sha256=document["contract_sha256"],
                timeline=cls._timeline_from_document(timeline_document),
                timeline_id=document["timeline_id"],
                application_id=document["application_id"],
                job_key=document["job_key"],
                released_application_sha256=document[
                    "released_application_sha256"
                ],
                draft_sha256=document["draft_sha256"],
                last_observed_at=document["last_observed_at"],
                due_at=document["due_at"],
                policy_sha256=document["policy_sha256"],
                idempotency_key=document["idempotency_key"],
                max_sends=document["max_sends"],
                sent_count=document["sent_count"],
                connector_authority=document["connector_authority"],
                send_authority=document["send_authority"],
                dependency_satisfied=document["dependency_satisfied"],
                production_certification=document[
                    "production_certification"
                ],
                certifies_slice=document["certifies_slice"],
                schema_version=document["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "follow-up intent reconstruction failed closed"
            ) from exc
        if _canonical_json(intent.document()) != _canonical_json(document):
            raise StatusEvidenceIntegrityError(
                "follow-up intent does not round trip"
            )
        return intent

    def archive_raw_export(
        self,
        evidence: RawStatusEvidence,
        raw_export_bytes: bytes,
    ) -> StatusEvidenceStoreReceipt:
        if not isinstance(evidence, RawStatusEvidence):
            raise TypeError(
                "raw export archive requires RawStatusEvidence"
            )
        evidence.verify()
        if evidence.contract_sha256 != self.identity.contract_sha256:
            raise ValueError("raw export binds a different status contract")
        if not isinstance(raw_export_bytes, bytes) or not raw_export_bytes:
            raise ValueError("raw local export bytes are required")
        if hashlib.sha256(raw_export_bytes).hexdigest() != evidence.source_sha256:
            raise ValueError("raw export bytes differ from source hash")
        evidence_json = _canonical_json(evidence.document())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._verify_connection(connection)
            existing = connection.execute(
                """
                SELECT evidence_json, source_sha256, receipt_sha256
                FROM raw_evidence_binding WHERE evidence_id = ?
                """,
                (evidence.evidence_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["evidence_json"] != evidence_json
                    or existing["source_sha256"] != evidence.source_sha256
                    or self._blob_bytes(connection, evidence.source_sha256)
                    != raw_export_bytes
                ):
                    raise StatusEvidenceConflictError(
                        "raw evidence identity already has different content"
                    )
                connection.rollback()
                return self._receipt_by_sha256(
                    connection,
                    existing["receipt_sha256"],
                )
            blob = connection.execute(
                """
                SELECT raw_bytes, byte_count FROM raw_export_blob
                WHERE source_sha256 = ?
                """,
                (evidence.source_sha256,),
            ).fetchone()
            blob_created = blob is None
            if blob is not None and (
                bytes(blob["raw_bytes"]) != raw_export_bytes
                or blob["byte_count"] != len(raw_export_bytes)
            ):
                raise StatusEvidenceConflictError(
                    "content-addressed raw export has different bytes"
                )
            receipt = self._next_receipt(
                snapshot,
                event_type="archive_raw_export",
                payload={
                    "evidence_id": evidence.evidence_id,
                    "source_sha256": evidence.source_sha256,
                    "evidence_document_sha256": _content_hash(
                        evidence.document()
                    ),
                    "byte_count": len(raw_export_bytes),
                    "blob_created": blob_created,
                    "untrusted_content": True,
                    "instruction_authority": False,
                    "candidate_fact_authority": False,
                },
            )
            self._insert_receipt(connection, receipt)
            if blob_created:
                connection.execute(
                    """
                    INSERT INTO raw_export_blob (
                        source_sha256, raw_bytes, byte_count,
                        first_receipt_sha256, integrity_sha256
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        evidence.source_sha256,
                        raw_export_bytes,
                        len(raw_export_bytes),
                        receipt.receipt_sha256,
                        _content_hash({
                            "source_sha256": evidence.source_sha256,
                            "byte_count": len(raw_export_bytes),
                            "untrusted_content": True,
                        }),
                    ),
                )
            connection.execute(
                """
                INSERT INTO raw_evidence_binding (
                    evidence_id, source_sha256, application_id, job_key,
                    source_record_id, observed_at, evidence_json,
                    receipt_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.evidence_id,
                    evidence.source_sha256,
                    evidence.application_id,
                    evidence.job_key,
                    evidence.source_record_id,
                    evidence.observed_at,
                    evidence_json,
                    receipt.receipt_sha256,
                ),
            )
            next_snapshot = self._snapshot_from_counts(
                connection,
                receipt,
            )
            self._write_state(connection, next_snapshot)
            connection.commit()
            return receipt
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def read_raw_export(self, evidence: RawStatusEvidence) -> bytes:
        if not isinstance(evidence, RawStatusEvidence):
            raise TypeError("raw export read requires RawStatusEvidence")
        evidence.verify()
        connection = self._connect()
        try:
            self._verify_connection(connection)
            row = connection.execute(
                """
                SELECT evidence_json, source_sha256
                FROM raw_evidence_binding WHERE evidence_id = ?
                """,
                (evidence.evidence_id,),
            ).fetchone()
            if (
                row is None
                or row["evidence_json"]
                != _canonical_json(evidence.document())
                or row["source_sha256"] != evidence.source_sha256
            ):
                raise StatusEvidenceIntegrityError(
                    "raw evidence binding is absent or different"
                )
            return self._blob_bytes(connection, evidence.source_sha256)
        except StatusEvidenceIntegrityError:
            raise
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            raise StatusEvidenceIntegrityError(
                "raw export re-authentication failed closed"
            ) from exc
        finally:
            connection.close()

    def append_observation(
        self,
        observation: StatusObservation,
    ) -> StatusEvidenceStoreReceipt:
        if not isinstance(observation, StatusObservation):
            raise TypeError(
                "status evidence append requires StatusObservation"
            )
        observation.verify()
        if observation.raw_evidence.contract_sha256 != self.identity.contract_sha256:
            raise ValueError(
                "status observation binds a different status contract"
            )
        observation_json = _canonical_json(observation.document())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._verify_connection(connection)
            existing = connection.execute(
                """
                SELECT content_json, receipt_sha256
                FROM status_observation WHERE observation_id = ?
                """,
                (observation.observation_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_json"] != observation_json:
                    raise StatusEvidenceConflictError(
                        "observation identity already has different content"
                    )
                connection.rollback()
                return self._receipt_by_sha256(
                    connection,
                    existing["receipt_sha256"],
                )
            self._require_archived_evidence(
                connection,
                observation.raw_evidence,
            )
            stream = connection.execute(
                """
                SELECT observation_count, last_observed_at,
                       current_state, terminal_state
                FROM status_application_stream
                WHERE application_id = ? AND job_key = ?
                """,
                (observation.application_id, observation.job_key),
            ).fetchone()
            if stream is None:
                observation_count = 0
                prior_state = PipelineState.RECEIPT_CONFIRMED
                terminal_state = None
            else:
                observation_count = int(stream["observation_count"])
                prior_state = PipelineState(stream["current_state"])
                terminal_state = stream["terminal_state"]
                if (
                    _parsed_datetime(observation.observed_at)
                    <= _parsed_datetime(stream["last_observed_at"])
                ):
                    raise StatusEvidenceStateError(
                        "status observations must be strictly monotonic"
                    )
            target_state = observation.classified_state
            next_state = prior_state
            if target_state is not None and target_state is not prior_state:
                if target_state not in LEGAL_TRANSITIONS[prior_state]:
                    raise StatusEvidenceStateError(
                        "durable status transition is illegal"
                    )
                next_state = target_state
            if terminal_state is not None and next_state.value != terminal_state:
                raise StatusEvidenceStateError(
                    "durable terminal status cannot be reversed"
                )
            next_terminal = (
                next_state.value
                if next_state in TERMINAL_STATUS_STATES
                else terminal_state
            )
            stream_sequence = observation_count + 1
            receipt = self._next_receipt(
                snapshot,
                event_type="append_observation",
                payload={
                    "application_id": observation.application_id,
                    "job_key": observation.job_key,
                    "stream_sequence": stream_sequence,
                    "observation_id": observation.observation_id,
                    "observation_document_sha256": _content_hash(
                        observation.document()
                    ),
                    "raw_evidence_id": observation.raw_evidence_id,
                    "observed_at": observation.observed_at,
                    "prior_state": prior_state.value,
                    "next_state": next_state.value,
                    "terminal_state": next_terminal,
                },
            )
            self._insert_receipt(connection, receipt)
            connection.execute(
                """
                INSERT INTO status_observation (
                    application_id, job_key, stream_sequence,
                    observation_id, raw_evidence_id, source_record_id,
                    observed_at, classified_state, content_json,
                    receipt_sha256, receipt_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation.application_id,
                    observation.job_key,
                    stream_sequence,
                    observation.observation_id,
                    observation.raw_evidence_id,
                    observation.source_record_id,
                    observation.observed_at,
                    None
                    if observation.classified_state is None
                    else observation.classified_state.value,
                    observation_json,
                    receipt.receipt_sha256,
                    receipt.document["sequence"],
                ),
            )
            stream_document = {
                "application_id": observation.application_id,
                "job_key": observation.job_key,
                "observation_count": stream_sequence,
                "last_observed_at": observation.observed_at,
                "current_state": next_state.value,
                "terminal_state": next_terminal,
            }
            if stream is None:
                connection.execute(
                    """
                    INSERT INTO status_application_stream (
                        application_id, job_key, observation_count,
                        last_observed_at, current_state, terminal_state,
                        stream_integrity_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observation.application_id,
                        observation.job_key,
                        stream_sequence,
                        observation.observed_at,
                        next_state.value,
                        next_terminal,
                        _content_hash(stream_document),
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE status_application_stream SET
                        observation_count = ?, last_observed_at = ?,
                        current_state = ?, terminal_state = ?,
                        stream_integrity_sha256 = ?
                    WHERE application_id = ? AND job_key = ?
                    """,
                    (
                        stream_sequence,
                        observation.observed_at,
                        next_state.value,
                        next_terminal,
                        _content_hash(stream_document),
                        observation.application_id,
                        observation.job_key,
                    ),
                )
            next_snapshot = self._snapshot_from_counts(connection, receipt)
            self._write_state(connection, next_snapshot)
            connection.commit()
            return receipt
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def register_timeline(
        self,
        timeline: StatusTimeline,
    ) -> StatusEvidenceStoreReceipt:
        if not isinstance(timeline, StatusTimeline):
            raise TypeError(
                "timeline registration requires StatusTimeline"
            )
        timeline.verify()
        if timeline.contract_sha256 != self.identity.contract_sha256:
            raise ValueError("timeline binds a different status contract")
        timeline_json = _canonical_json(timeline.document())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._verify_connection(connection)
            count = self._require_current_timeline(connection, timeline)
            existing = connection.execute(
                """
                SELECT content_json, receipt_sha256
                FROM status_timeline_registration WHERE timeline_id = ?
                """,
                (timeline.timeline_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_json"] != timeline_json:
                    raise StatusEvidenceConflictError(
                        "timeline identity already has different content"
                    )
                connection.rollback()
                return self._receipt_by_sha256(
                    connection,
                    existing["receipt_sha256"],
                )
            receipt = self._next_receipt(
                snapshot,
                event_type="register_timeline",
                payload={
                    "application_id": timeline.application_id,
                    "job_key": timeline.job_key,
                    "timeline_id": timeline.timeline_id,
                    "timeline_document_sha256": _content_hash(
                        timeline.document()
                    ),
                    "observation_count": count,
                    "final_state": timeline.final_state.value,
                },
            )
            self._insert_receipt(connection, receipt)
            connection.execute(
                """
                INSERT INTO status_timeline_registration (
                    timeline_id, application_id, job_key,
                    observation_count, final_state, content_json,
                    receipt_sha256, receipt_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timeline.timeline_id,
                    timeline.application_id,
                    timeline.job_key,
                    count,
                    timeline.final_state.value,
                    timeline_json,
                    receipt.receipt_sha256,
                    receipt.document["sequence"],
                ),
            )
            next_snapshot = self._snapshot_from_counts(connection, receipt)
            self._write_state(connection, next_snapshot)
            connection.commit()
            return receipt
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def register_follow_up_intent(
        self,
        intent: FollowUpIntent,
    ) -> StatusEvidenceStoreReceipt:
        if not isinstance(intent, FollowUpIntent):
            raise TypeError(
                "follow-up registration requires FollowUpIntent"
            )
        intent.__post_init__()
        if intent.contract_sha256 != self.identity.contract_sha256:
            raise ValueError(
                "follow-up intent binds a different status contract"
            )
        intent_json = _canonical_json(intent.document())
        intent_sha256 = intent.intent_sha256
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._verify_connection(connection)
            stream = connection.execute(
                """
                SELECT terminal_state FROM status_application_stream
                WHERE application_id = ? AND job_key = ?
                """,
                (intent.application_id, intent.job_key),
            ).fetchone()
            if stream is not None and stream["terminal_state"] is not None:
                raise StatusEvidenceStateError(
                    "durable terminal status blocks follow-up registration"
                )
            count = self._require_current_timeline(
                connection,
                intent.timeline,
            )
            registered = connection.execute(
                """
                SELECT observation_count, content_json
                FROM status_timeline_registration
                WHERE timeline_id = ?
                """,
                (intent.timeline_id,),
            ).fetchone()
            if (
                registered is None
                or int(registered["observation_count"]) != count
                or registered["content_json"]
                != _canonical_json(intent.timeline.document())
            ):
                raise StatusEvidenceStateError(
                    "follow-up requires the registered current timeline"
                )
            existing = connection.execute(
                """
                SELECT intent_sha256, content_json, receipt_sha256
                FROM follow_up_intent_registration
                WHERE idempotency_key = ?
                """,
                (intent.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["intent_sha256"] != intent_sha256
                    or existing["content_json"] != intent_json
                ):
                    raise StatusEvidenceConflictError(
                        "follow-up idempotency key already binds another intent"
                    )
                connection.rollback()
                return self._receipt_by_sha256(
                    connection,
                    existing["receipt_sha256"],
                )
            receipt = self._next_receipt(
                snapshot,
                event_type="register_follow_up_intent",
                payload={
                    "application_id": intent.application_id,
                    "job_key": intent.job_key,
                    "timeline_id": intent.timeline_id,
                    "observation_count": count,
                    "idempotency_key": intent.idempotency_key,
                    "intent_sha256": intent_sha256,
                    "draft_sha256": intent.draft_sha256,
                    "released_application_sha256": (
                        intent.released_application_sha256
                    ),
                    "dispatch_state": "unrepresentable",
                },
            )
            self._insert_receipt(connection, receipt)
            connection.execute(
                """
                INSERT INTO follow_up_intent_registration (
                    idempotency_key, intent_sha256, application_id,
                    job_key, timeline_id, observation_count,
                    draft_sha256, released_application_sha256,
                    content_json, receipt_sha256, receipt_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intent.idempotency_key,
                    intent_sha256,
                    intent.application_id,
                    intent.job_key,
                    intent.timeline_id,
                    count,
                    intent.draft_sha256,
                    intent.released_application_sha256,
                    intent_json,
                    receipt.receipt_sha256,
                    receipt.document["sequence"],
                ),
            )
            next_snapshot = self._snapshot_from_counts(connection, receipt)
            self._write_state(connection, next_snapshot)
            connection.commit()
            return receipt
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _next_receipt(
        self,
        snapshot: StatusEvidenceStoreSnapshot,
        *,
        event_type: str,
        payload: Mapping[str, object],
    ) -> StatusEvidenceStoreReceipt:
        return _receipt(
            (
                self.identity.contract_sha256,
                self.identity.store_instance_id,
            ),
            event_type=event_type,
            sequence=snapshot.receipt_sequence + 1,
            previous_receipt_sha256=snapshot.head_receipt_sha256,
            payload=payload,
        )

    @staticmethod
    def _insert_receipt(
        connection: sqlite3.Connection,
        receipt: StatusEvidenceStoreReceipt,
    ) -> None:
        connection.execute(
            """
            INSERT INTO status_store_receipt (
                sequence, event_type, receipt_sha256,
                previous_receipt_sha256, content_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                receipt.document["sequence"],
                receipt.document["event_type"],
                receipt.receipt_sha256,
                receipt.document["previous_receipt_sha256"],
                _canonical_json(dict(receipt.document)),
            ),
        )

    @staticmethod
    def _receipt_by_sha256(
        connection: sqlite3.Connection,
        receipt_sha256: str,
    ) -> StatusEvidenceStoreReceipt:
        row = connection.execute(
            """
            SELECT content_json FROM status_store_receipt
            WHERE receipt_sha256 = ?
            """,
            (receipt_sha256,),
        ).fetchone()
        if row is None:
            raise StatusEvidenceIntegrityError(
                "referenced durable receipt is absent"
            )
        return StatusEvidenceStoreReceipt(
            receipt_sha256,
            json.loads(row["content_json"]),
        )

    @staticmethod
    def _blob_bytes(
        connection: sqlite3.Connection,
        source_sha256: str,
    ) -> bytes:
        row = connection.execute(
            """
            SELECT raw_bytes, byte_count FROM raw_export_blob
            WHERE source_sha256 = ?
            """,
            (source_sha256,),
        ).fetchone()
        if row is None:
            raise StatusEvidenceIntegrityError(
                "content-addressed raw export is absent"
            )
        raw_bytes = bytes(row["raw_bytes"])
        if (
            len(raw_bytes) != int(row["byte_count"])
            or hashlib.sha256(raw_bytes).hexdigest() != source_sha256
        ):
            raise StatusEvidenceIntegrityError(
                "content-addressed raw export failed re-authentication"
            )
        return raw_bytes

    def _require_archived_evidence(
        self,
        connection: sqlite3.Connection,
        evidence: RawStatusEvidence,
    ) -> None:
        row = connection.execute(
            """
            SELECT source_sha256, evidence_json
            FROM raw_evidence_binding WHERE evidence_id = ?
            """,
            (evidence.evidence_id,),
        ).fetchone()
        if (
            row is None
            or row["source_sha256"] != evidence.source_sha256
            or row["evidence_json"] != _canonical_json(evidence.document())
        ):
            raise StatusEvidenceStateError(
                "status observation requires exact archived raw evidence"
            )
        self._blob_bytes(connection, evidence.source_sha256)

    @staticmethod
    def _require_current_timeline(
        connection: sqlite3.Connection,
        timeline: StatusTimeline,
    ) -> int:
        rows = connection.execute(
            """
            SELECT content_json FROM status_observation
            WHERE application_id = ? AND job_key = ?
            ORDER BY stream_sequence
            """,
            (timeline.application_id, timeline.job_key),
        ).fetchall()
        durable_documents = tuple(
            json.loads(row["content_json"]) for row in rows
        )
        timeline_documents = tuple(
            row.document() for row in timeline.observations
        )
        if durable_documents != timeline_documents:
            raise StatusEvidenceStateError(
                "timeline must contain the complete durable observation set"
            )
        return len(rows)

    def _snapshot_from_counts(
        self,
        connection: sqlite3.Connection,
        receipt: StatusEvidenceStoreReceipt,
    ) -> StatusEvidenceStoreSnapshot:
        def count(table: str) -> int:
            return int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
            )

        return StatusEvidenceStoreSnapshot(
            receipt_sequence=int(receipt.document["sequence"]),
            head_receipt_sha256=receipt.receipt_sha256,
            raw_blob_count=count("raw_export_blob"),
            raw_evidence_count=count("raw_evidence_binding"),
            observation_count=count("status_observation"),
            timeline_count=count("status_timeline_registration"),
            intent_count=count("follow_up_intent_registration"),
        )

    def _verify_connection(
        self,
        connection: sqlite3.Connection,
    ) -> StatusEvidenceStoreSnapshot:
        metadata = connection.execute(
            "SELECT * FROM status_store_metadata"
        ).fetchall()
        if len(metadata) != 1:
            raise StatusEvidenceIntegrityError(
                "status evidence metadata cardinality is invalid"
            )
        policy = status_evidence_store_policy()
        if (
            metadata[0]["schema_version"] != STORE_SCHEMA_VERSION
            or metadata[0]["policy_json"] != _canonical_json(policy)
            or metadata[0]["policy_sha256"] != _content_hash(policy)
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence policy differs from accepted bytes"
            )
        state_rows = connection.execute(
            "SELECT * FROM status_store_state"
        ).fetchall()
        if len(state_rows) != 1:
            raise StatusEvidenceIntegrityError(
                "status evidence state cardinality is invalid"
            )
        state = state_rows[0]
        stored_identity = StatusEvidenceStoreIdentity(
            state["contract_sha256"],
            state["store_instance_id"],
            state["genesis_receipt_sha256"],
        )
        if stored_identity != self.identity:
            raise StatusEvidenceIntegrityError(
                "status evidence store identity is not the pinned identity"
            )
        snapshot = StatusEvidenceStoreSnapshot(
            receipt_sequence=int(state["receipt_sequence"]),
            head_receipt_sha256=state["head_receipt_sha256"],
            raw_blob_count=int(state["raw_blob_count"]),
            raw_evidence_count=int(state["raw_evidence_count"]),
            observation_count=int(state["observation_count"]),
            timeline_count=int(state["timeline_count"]),
            intent_count=int(state["intent_count"]),
        )
        if state["state_integrity_sha256"] != _content_hash(
            _state_document(self.identity, snapshot)
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence state integrity differs"
            )
        receipts = connection.execute(
            "SELECT * FROM status_store_receipt ORDER BY sequence"
        ).fetchall()
        if (
            len(receipts) != snapshot.receipt_sequence + 1
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence receipt sequence is incomplete"
            )
        previous = GENESIS_LINK
        receipt_documents: dict[str, dict[str, object]] = {}
        for sequence, row in enumerate(receipts):
            document = json.loads(row["content_json"])
            receipt = StatusEvidenceStoreReceipt(
                row["receipt_sha256"],
                document,
            )
            if (
                int(row["sequence"]) != sequence
                or row["content_json"] != _canonical_json(document)
                or document.get("sequence") != sequence
                or row["event_type"] != document.get("event_type")
                or row["previous_receipt_sha256"] != previous
                or document.get("previous_receipt_sha256") != previous
                or document.get("schema_version")
                != RECEIPT_SCHEMA_VERSION
                or document.get("policy_version") != POLICY_VERSION
                or document.get("contract_sha256")
                != self.identity.contract_sha256
                or document.get("store_instance_id")
                != self.identity.store_instance_id
                or document.get("connector_authority") != "withheld"
                or document.get("message_send_authority") != "withheld"
                or document.get("external_action_performed") is not False
            ):
                raise StatusEvidenceIntegrityError(
                    "status evidence receipt chain differs"
                )
            receipt_documents[receipt.receipt_sha256] = document
            previous = receipt.receipt_sha256
        if (
            receipts[0]["receipt_sha256"]
            != self.identity.genesis_receipt_sha256
            or receipts[0]["event_type"] != "initialize"
            or snapshot.head_receipt_sha256 != previous
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence genesis or head receipt differs"
            )
        genesis_payload = receipt_documents[
            self.identity.genesis_receipt_sha256
        ].get("payload")
        if (
            not isinstance(genesis_payload, dict)
            or not HEX_64.fullmatch(
                str(genesis_payload.get("initialization_nonce", ""))
            )
            or genesis_payload.get("raw_content_trust")
            != "untrusted_data_only"
            or genesis_payload.get("intent_dispatch_state")
            != "unrepresentable"
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence genesis payload differs"
            )
        self._verify_raw_archive(connection, receipt_documents)
        observations = self._verify_observations(
            connection,
            receipt_documents,
        )
        self._verify_timelines(
            connection,
            receipt_documents,
            observations,
        )
        self._verify_intents(
            connection,
            receipt_documents,
            observations,
        )
        actual = self._snapshot_from_existing_head(connection)
        if actual != snapshot:
            raise StatusEvidenceIntegrityError(
                "status evidence durable counts differ from state"
            )
        event_counts = {
            event: int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM status_store_receipt
                    WHERE event_type = ?
                    """,
                    (event,),
                ).fetchone()[0]
            )
            for event in (
                "initialize",
                "archive_raw_export",
                "append_observation",
                "register_timeline",
                "register_follow_up_intent",
            )
        }
        if (
            event_counts["initialize"] != 1
            or event_counts["archive_raw_export"]
            != snapshot.raw_evidence_count
            or event_counts["append_observation"]
            != snapshot.observation_count
            or event_counts["register_timeline"]
            != snapshot.timeline_count
            or event_counts["register_follow_up_intent"]
            != snapshot.intent_count
            or sum(event_counts.values()) != len(receipts)
        ):
            raise StatusEvidenceIntegrityError(
                "status evidence receipts do not cover every append"
            )
        return snapshot

    def _snapshot_from_existing_head(
        self,
        connection: sqlite3.Connection,
    ) -> StatusEvidenceStoreSnapshot:
        def count(table: str) -> int:
            return int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
            )

        head = connection.execute(
            """
            SELECT sequence, receipt_sha256 FROM status_store_receipt
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        if head is None:
            raise StatusEvidenceIntegrityError(
                "status evidence head receipt is absent"
            )
        return StatusEvidenceStoreSnapshot(
            receipt_sequence=int(head["sequence"]),
            head_receipt_sha256=head["receipt_sha256"],
            raw_blob_count=count("raw_export_blob"),
            raw_evidence_count=count("raw_evidence_binding"),
            observation_count=count("status_observation"),
            timeline_count=count("status_timeline_registration"),
            intent_count=count("follow_up_intent_registration"),
        )

    def _verify_raw_archive(
        self,
        connection: sqlite3.Connection,
        receipts: Mapping[str, Mapping[str, object]],
    ) -> None:
        blobs = connection.execute(
            "SELECT * FROM raw_export_blob"
        ).fetchall()
        for row in blobs:
            raw_bytes = bytes(row["raw_bytes"])
            source_sha256 = row["source_sha256"]
            if (
                hashlib.sha256(raw_bytes).hexdigest() != source_sha256
                or len(raw_bytes) != int(row["byte_count"])
                or row["integrity_sha256"] != _content_hash({
                    "source_sha256": source_sha256,
                    "byte_count": len(raw_bytes),
                    "untrusted_content": True,
                })
            ):
                raise StatusEvidenceIntegrityError(
                    "content-addressed raw archive differs"
                )
            receipt = receipts.get(row["first_receipt_sha256"])
            payload = {} if receipt is None else receipt.get("payload", {})
            if (
                receipt is None
                or receipt.get("event_type") != "archive_raw_export"
                or not isinstance(payload, dict)
                or payload.get("source_sha256") != source_sha256
                or payload.get("blob_created") is not True
            ):
                raise StatusEvidenceIntegrityError(
                    "raw archive creation receipt is absent"
                )
        bindings = connection.execute(
            "SELECT * FROM raw_evidence_binding"
        ).fetchall()
        for row in bindings:
            document = json.loads(row["evidence_json"])
            identity = document.get("evidence_id")
            body = dict(document)
            body.pop("evidence_id", None)
            receipt = receipts.get(row["receipt_sha256"])
            payload = {} if receipt is None else receipt.get("payload", {})
            if (
                identity != row["evidence_id"]
                or row["evidence_json"] != _canonical_json(document)
                or _content_hash(body) != row["evidence_id"]
                or document.get("source_sha256") != row["source_sha256"]
                or document.get("application_id") != row["application_id"]
                or document.get("job_key") != row["job_key"]
                or document.get("source_record_id")
                != row["source_record_id"]
                or document.get("observed_at") != row["observed_at"]
                or not isinstance(payload, dict)
                or receipt.get("event_type") != "archive_raw_export"
                or payload.get("evidence_id") != row["evidence_id"]
                or payload.get("source_sha256") != row["source_sha256"]
                or payload.get("evidence_document_sha256")
                != _content_hash(document)
            ):
                raise StatusEvidenceIntegrityError(
                    "raw evidence binding differs from exact content"
                )
            self._blob_bytes(connection, row["source_sha256"])

    def _verify_observations(
        self,
        connection: sqlite3.Connection,
        receipts: Mapping[str, Mapping[str, object]],
    ) -> dict[tuple[str, str], list[sqlite3.Row]]:
        rows = connection.execute(
            """
            SELECT * FROM status_observation
            ORDER BY application_id, job_key, stream_sequence
            """
        ).fetchall()
        grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in rows:
            document = json.loads(row["content_json"])
            identity = document.get("observation_id")
            body = dict(document)
            body.pop("observation_id", None)
            receipt = receipts.get(row["receipt_sha256"])
            payload = {} if receipt is None else receipt.get("payload", {})
            if (
                identity != row["observation_id"]
                or row["content_json"] != _canonical_json(document)
                or _content_hash(body) != row["observation_id"]
                or document.get("application_id") != row["application_id"]
                or document.get("job_key") != row["job_key"]
                or document.get("raw_evidence_id")
                != row["raw_evidence_id"]
                or document.get("source_record_id")
                != row["source_record_id"]
                or document.get("observed_at") != row["observed_at"]
                or document.get("classified_state")
                != row["classified_state"]
                or receipt is None
                or receipt.get("event_type") != "append_observation"
                or not isinstance(payload, dict)
                or payload.get("observation_id")
                != row["observation_id"]
                or payload.get("raw_evidence_id")
                != row["raw_evidence_id"]
                or payload.get("stream_sequence")
                != row["stream_sequence"]
                or receipt.get("sequence") != row["receipt_sequence"]
            ):
                raise StatusEvidenceIntegrityError(
                    "durable status observation differs"
                )
            binding = connection.execute(
                """
                SELECT evidence_json FROM raw_evidence_binding
                WHERE evidence_id = ?
                """,
                (row["raw_evidence_id"],),
            ).fetchone()
            if (
                binding is None
                or document.get("raw_evidence")
                != json.loads(binding["evidence_json"])
            ):
                raise StatusEvidenceIntegrityError(
                    "status observation raw evidence is not archived"
                )
            grouped.setdefault(
                (row["application_id"], row["job_key"]),
                [],
            ).append(row)
        streams = connection.execute(
            """
            SELECT * FROM status_application_stream
            ORDER BY application_id, job_key
            """
        ).fetchall()
        if len(streams) != len(grouped):
            raise StatusEvidenceIntegrityError(
                "status application stream cardinality differs"
            )
        for stream in streams:
            key = (stream["application_id"], stream["job_key"])
            stream_rows = grouped.get(key)
            if not stream_rows:
                raise StatusEvidenceIntegrityError(
                    "status application stream has no observations"
                )
            current = PipelineState.RECEIPT_CONFIRMED
            last_time = None
            terminal = None
            for index, row in enumerate(stream_rows, 1):
                observed_at = _parsed_datetime(row["observed_at"])
                target = (
                    None
                    if row["classified_state"] is None
                    else PipelineState(row["classified_state"])
                )
                if (
                    int(row["stream_sequence"]) != index
                    or (last_time is not None and observed_at <= last_time)
                ):
                    raise StatusEvidenceIntegrityError(
                        "status observation stream order differs"
                    )
                if target is not None and target is not current:
                    if target not in LEGAL_TRANSITIONS[current]:
                        raise StatusEvidenceIntegrityError(
                            "durable status transition is illegal"
                        )
                    current = target
                if current in TERMINAL_STATUS_STATES:
                    if terminal is None:
                        terminal = current.value
                    elif current.value != terminal:
                        raise StatusEvidenceIntegrityError(
                            "durable terminal state was reversed"
                        )
                last_time = observed_at
            stream_document = {
                "application_id": key[0],
                "job_key": key[1],
                "observation_count": len(stream_rows),
                "last_observed_at": stream_rows[-1]["observed_at"],
                "current_state": current.value,
                "terminal_state": terminal,
            }
            if (
                int(stream["observation_count"]) != len(stream_rows)
                or stream["last_observed_at"]
                != stream_rows[-1]["observed_at"]
                or stream["current_state"] != current.value
                or stream["terminal_state"] != terminal
                or stream["stream_integrity_sha256"]
                != _content_hash(stream_document)
            ):
                raise StatusEvidenceIntegrityError(
                    "status application stream differs from observations"
                )
        return grouped

    def _verify_timelines(
        self,
        connection: sqlite3.Connection,
        receipts: Mapping[str, Mapping[str, object]],
        observations: Mapping[tuple[str, str], list[sqlite3.Row]],
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM status_timeline_registration"
        ).fetchall()
        for row in rows:
            document = json.loads(row["content_json"])
            identity = document.get("timeline_id")
            body = dict(document)
            body.pop("timeline_id", None)
            receipt = receipts.get(row["receipt_sha256"])
            payload = {} if receipt is None else receipt.get("payload", {})
            stream_rows = observations.get(
                (row["application_id"], row["job_key"]),
                [],
            )
            prefix = stream_rows[: int(row["observation_count"])]
            prefix_documents = [
                json.loads(item["content_json"]) for item in prefix
            ]
            prior_count = sum(
                1
                for item in stream_rows
                if int(item["receipt_sequence"])
                < int(row["receipt_sequence"])
            )
            if (
                identity != row["timeline_id"]
                or row["content_json"] != _canonical_json(document)
                or _content_hash(body) != row["timeline_id"]
                or document.get("application_id") != row["application_id"]
                or document.get("job_key") != row["job_key"]
                or document.get("observations") != prefix_documents
                or prior_count != int(row["observation_count"])
                or len(prefix) != int(row["observation_count"])
                or document.get("final_state") != row["final_state"]
                or receipt is None
                or receipt.get("event_type") != "register_timeline"
                or not isinstance(payload, dict)
                or payload.get("timeline_id") != row["timeline_id"]
                or receipt.get("sequence") != row["receipt_sequence"]
            ):
                raise StatusEvidenceIntegrityError(
                    "durable timeline registration differs"
                )

    def _verify_intents(
        self,
        connection: sqlite3.Connection,
        receipts: Mapping[str, Mapping[str, object]],
        observations: Mapping[tuple[str, str], list[sqlite3.Row]],
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM follow_up_intent_registration"
        ).fetchall()
        for row in rows:
            document = json.loads(row["content_json"])
            receipt = receipts.get(row["receipt_sha256"])
            payload = {} if receipt is None else receipt.get("payload", {})
            timeline = connection.execute(
                """
                SELECT content_json, observation_count, receipt_sequence
                FROM status_timeline_registration
                WHERE timeline_id = ?
                """,
                (row["timeline_id"],),
            ).fetchone()
            stream_rows = observations.get(
                (row["application_id"], row["job_key"]),
                [],
            )
            prior_rows = [
                item
                for item in stream_rows
                if int(item["receipt_sequence"])
                < int(row["receipt_sequence"])
            ]
            current = PipelineState.RECEIPT_CONFIRMED
            for item in prior_rows:
                if item["classified_state"] is None:
                    continue
                target = PipelineState(item["classified_state"])
                if target is not current:
                    current = target
            if (
                row["content_json"] != _canonical_json(document)
                or
                _content_hash(document) != row["intent_sha256"]
                or document.get("idempotency_key")
                != row["idempotency_key"]
                or document.get("application_id") != row["application_id"]
                or document.get("job_key") != row["job_key"]
                or document.get("timeline_id") != row["timeline_id"]
                or document.get("draft_sha256") != row["draft_sha256"]
                or document.get("released_application_sha256")
                != row["released_application_sha256"]
                or document.get("sent_count") != 0
                or document.get("send_authority") != "withheld"
                or document.get("connector_authority") != "withheld"
                or timeline is None
                or document.get("timeline")
                != json.loads(timeline["content_json"])
                or int(timeline["observation_count"])
                != int(row["observation_count"])
                or int(timeline["receipt_sequence"])
                >= int(row["receipt_sequence"])
                or len(prior_rows) != int(row["observation_count"])
                or current in TERMINAL_STATUS_STATES
                or receipt is None
                or receipt.get("event_type")
                != "register_follow_up_intent"
                or not isinstance(payload, dict)
                or payload.get("intent_sha256") != row["intent_sha256"]
                or payload.get("idempotency_key")
                != row["idempotency_key"]
                or payload.get("dispatch_state") != "unrepresentable"
                or receipt.get("sequence") != row["receipt_sequence"]
            ):
                raise StatusEvidenceIntegrityError(
                    "durable follow-up intent differs"
                )


def _parsed_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("durable status time must include a timezone")
    return parsed


_SCHEMA = """
CREATE TABLE status_store_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL
);
CREATE TABLE status_store_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    contract_sha256 TEXT NOT NULL,
    store_instance_id TEXT NOT NULL,
    genesis_receipt_sha256 TEXT NOT NULL,
    receipt_sequence INTEGER NOT NULL CHECK (receipt_sequence >= 0),
    head_receipt_sha256 TEXT NOT NULL,
    raw_blob_count INTEGER NOT NULL CHECK (raw_blob_count >= 0),
    raw_evidence_count INTEGER NOT NULL CHECK (raw_evidence_count >= 0),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    timeline_count INTEGER NOT NULL CHECK (timeline_count >= 0),
    intent_count INTEGER NOT NULL CHECK (intent_count >= 0),
    state_integrity_sha256 TEXT NOT NULL
);
CREATE TABLE status_store_receipt (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    event_type TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    previous_receipt_sha256 TEXT NOT NULL,
    content_json TEXT NOT NULL
);
CREATE TABLE raw_export_blob (
    source_sha256 TEXT PRIMARY KEY,
    raw_bytes BLOB NOT NULL,
    byte_count INTEGER NOT NULL CHECK (byte_count > 0),
    first_receipt_sha256 TEXT NOT NULL,
    integrity_sha256 TEXT NOT NULL
);
CREATE TABLE raw_evidence_binding (
    evidence_id TEXT PRIMARY KEY,
    source_sha256 TEXT NOT NULL REFERENCES raw_export_blob(source_sha256),
    application_id TEXT NOT NULL,
    job_key TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE
        REFERENCES status_store_receipt(receipt_sha256),
    UNIQUE (application_id, job_key, source_record_id)
);
CREATE TABLE status_application_stream (
    application_id TEXT NOT NULL,
    job_key TEXT NOT NULL,
    observation_count INTEGER NOT NULL CHECK (observation_count > 0),
    last_observed_at TEXT NOT NULL,
    current_state TEXT NOT NULL,
    terminal_state TEXT,
    stream_integrity_sha256 TEXT NOT NULL,
    PRIMARY KEY (application_id, job_key)
);
CREATE TABLE status_observation (
    application_id TEXT NOT NULL,
    job_key TEXT NOT NULL,
    stream_sequence INTEGER NOT NULL CHECK (stream_sequence > 0),
    observation_id TEXT NOT NULL UNIQUE,
    raw_evidence_id TEXT NOT NULL UNIQUE
        REFERENCES raw_evidence_binding(evidence_id),
    source_record_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    classified_state TEXT,
    content_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE
        REFERENCES status_store_receipt(receipt_sha256),
    receipt_sequence INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (application_id, job_key, stream_sequence),
    UNIQUE (application_id, job_key, source_record_id),
    UNIQUE (application_id, job_key, observed_at)
);
CREATE TABLE status_timeline_registration (
    timeline_id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    job_key TEXT NOT NULL,
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    final_state TEXT NOT NULL,
    content_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE
        REFERENCES status_store_receipt(receipt_sha256),
    receipt_sequence INTEGER NOT NULL UNIQUE
);
CREATE TABLE follow_up_intent_registration (
    idempotency_key TEXT PRIMARY KEY,
    intent_sha256 TEXT NOT NULL UNIQUE,
    application_id TEXT NOT NULL,
    job_key TEXT NOT NULL,
    timeline_id TEXT NOT NULL
        REFERENCES status_timeline_registration(timeline_id),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    draft_sha256 TEXT NOT NULL,
    released_application_sha256 TEXT NOT NULL,
    content_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE
        REFERENCES status_store_receipt(receipt_sha256),
    receipt_sequence INTEGER NOT NULL UNIQUE
);
CREATE TRIGGER no_update_status_store_metadata
BEFORE UPDATE ON status_store_metadata BEGIN
    SELECT RAISE(ABORT, 'status store metadata is immutable');
END;
CREATE TRIGGER no_delete_status_store_metadata
BEFORE DELETE ON status_store_metadata BEGIN
    SELECT RAISE(ABORT, 'status store metadata is immutable');
END;
CREATE TRIGGER no_update_status_store_receipt
BEFORE UPDATE ON status_store_receipt BEGIN
    SELECT RAISE(ABORT, 'status store receipts are append-only');
END;
CREATE TRIGGER no_delete_status_store_receipt
BEFORE DELETE ON status_store_receipt BEGIN
    SELECT RAISE(ABORT, 'status store receipts are append-only');
END;
CREATE TRIGGER no_update_raw_export_blob
BEFORE UPDATE ON raw_export_blob BEGIN
    SELECT RAISE(ABORT, 'raw export blobs are immutable');
END;
CREATE TRIGGER no_delete_raw_export_blob
BEFORE DELETE ON raw_export_blob BEGIN
    SELECT RAISE(ABORT, 'raw export blobs are immutable');
END;
CREATE TRIGGER no_update_raw_evidence_binding
BEFORE UPDATE ON raw_evidence_binding BEGIN
    SELECT RAISE(ABORT, 'raw evidence bindings are immutable');
END;
CREATE TRIGGER no_delete_raw_evidence_binding
BEFORE DELETE ON raw_evidence_binding BEGIN
    SELECT RAISE(ABORT, 'raw evidence bindings are immutable');
END;
CREATE TRIGGER no_update_status_observation
BEFORE UPDATE ON status_observation BEGIN
    SELECT RAISE(ABORT, 'status observations are append-only');
END;
CREATE TRIGGER no_delete_status_observation
BEFORE DELETE ON status_observation BEGIN
    SELECT RAISE(ABORT, 'status observations are append-only');
END;
CREATE TRIGGER no_update_status_timeline_registration
BEFORE UPDATE ON status_timeline_registration BEGIN
    SELECT RAISE(ABORT, 'status timelines are append-only');
END;
CREATE TRIGGER no_delete_status_timeline_registration
BEFORE DELETE ON status_timeline_registration BEGIN
    SELECT RAISE(ABORT, 'status timelines are append-only');
END;
CREATE TRIGGER no_update_follow_up_intent_registration
BEFORE UPDATE ON follow_up_intent_registration BEGIN
    SELECT RAISE(ABORT, 'follow-up intents are append-only');
END;
CREATE TRIGGER no_delete_follow_up_intent_registration
BEFORE DELETE ON follow_up_intent_registration BEGIN
    SELECT RAISE(ABORT, 'follow-up intents are append-only');
END;
"""
