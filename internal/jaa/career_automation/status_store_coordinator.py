"""Local-only composition of JAA-12 status ingestion and durable storage.

The coordinator adds no I/O of its own.  It composes the accepted pure
local-export contract with a caller-supplied :class:`StatusEvidenceStore`.
Each store step commits independently, so successful prefixes remain truthful
durable progress when a later step fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Mapping

from career_automation.status_evidence_store import (
    StatusEvidenceStore,
    StatusEvidenceStoreReceipt,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    CensoredSilence,
    FollowUpIntent,
    RawStatusEvidence,
    StatusObservation,
    StatusTimeline,
    classify_status_evidence,
    compile_follow_up_intent,
    compile_local_export_evidence,
    compile_status_timeline,
)


COORDINATOR_POLICY_SHA256 = (
    "1c3874eaea9df15413984923f871aa135"
    "5a46b4fa5e0263b8c41f0d42b6383bd"
)
COORDINATOR_SCHEMA_VERSION = "jaa12.status-store-coordinator-policy.v1"
PIPELINE_ORDER = (
    "compile_local_export_evidence",
    "archive_raw_export",
    "classify_status_evidence",
    "append_observation",
    "compile_status_timeline",
    "register_timeline",
    "compile_follow_up_intent_if_requested",
    "register_follow_up_intent_if_requested",
)


@dataclass(frozen=True)
class _FrozenMapping(Mapping[str, object]):
    """Small immutable mapping without adding another stdlib dependency."""

    items: tuple[tuple[str, object], ...]

    def __getitem__(self, key: str) -> object:
        for candidate, value in self.items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self.items)

    def __len__(self) -> int:
        return len(self.items)


COORDINATOR_POLICY: Mapping[str, object] = _FrozenMapping((
    ("schema_version", COORDINATOR_SCHEMA_VERSION),
    (
        "contract_sha256",
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256,
    ),
    ("pipeline_order", PIPELINE_ORDER),
    ("partial_progress", "truthful_receipted_steps"),
    ("atomicity_across_steps", "absent"),
    ("durable_read_api", "absent"),
    (
        "follow_up_reference_hashes",
        "caller_supplied_structural_references",
    ),
    ("connector_authority", "withheld"),
    ("mailbox_access", "withheld"),
    ("portal_access", "withheld"),
    ("send_authority", "withheld"),
    ("objective_satisfied", False),
    ("dependency_satisfied", False),
    ("production_certification", "withheld"),
    ("certifies_slice", False),
    ("external_action_capability", False),
))


def status_store_coordinator_policy() -> dict[str, object]:
    """Return a mutable copy of the frozen, non-authorizing policy."""
    return dict(COORDINATOR_POLICY)


def _digest(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _receipt_document(
    receipt: StatusEvidenceStoreReceipt,
    expected_event_type: str,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    if not isinstance(receipt, StatusEvidenceStoreReceipt):
        raise TypeError("coordinator result receipts must be typed")
    receipt.__post_init__()
    document = receipt.document
    payload = document.get("payload")
    if (
        document.get("event_type") != expected_event_type
        or not isinstance(payload, Mapping)
        or document.get("external_action_performed") is not False
        or document.get("connector_authority") != "withheld"
        or document.get("message_send_authority") != "withheld"
    ):
        raise ValueError(
            "coordinator receipt differs from the durable store contract"
        )
    return document, payload


@dataclass(frozen=True)
class FollowUpRegistrationRequest:
    """Caller-supplied structural references for a non-sendable intent."""

    released_application_sha256: str
    draft_sha256: str

    def __post_init__(self) -> None:
        _digest(
            self.released_application_sha256,
            "released application hash",
        )
        _digest(self.draft_sha256, "follow-up draft hash")


@dataclass(frozen=True)
class LocalExportIngestionResult:
    """Exact typed values and receipts from one composed ingestion attempt."""

    evidence: RawStatusEvidence
    observation: StatusObservation
    timeline: StatusTimeline
    archive_receipt: StatusEvidenceStoreReceipt
    observation_receipt: StatusEvidenceStoreReceipt
    timeline_receipt: StatusEvidenceStoreReceipt
    intent: FollowUpIntent | None
    intent_receipt: StatusEvidenceStoreReceipt | None
    policy_sha256: str = COORDINATOR_POLICY_SHA256
    partial_progress: str = "truthful_receipted_steps"
    atomicity_across_steps: str = "absent"
    durable_read_api: str = "absent"
    follow_up_reference_hashes: str = (
        "caller_supplied_structural_references"
    )
    connector_authority: str = "withheld"
    send_authority: str = "withheld"
    objective_satisfied: bool = False
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    external_action_capability: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, RawStatusEvidence):
            raise TypeError("coordinator result requires typed evidence")
        if not isinstance(self.observation, StatusObservation):
            raise TypeError("coordinator result requires typed observation")
        if not isinstance(self.timeline, StatusTimeline):
            raise TypeError("coordinator result requires typed timeline")
        self.evidence.verify()
        self.observation.verify()
        self.timeline.verify()
        if (
            self.observation.raw_evidence != self.evidence
            or not self.timeline.observations
            or self.timeline.observations[-1] != self.observation
            or self.timeline.contract_sha256
            != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
        ):
            raise ValueError(
                "coordinator result typed values do not form one pipeline"
            )

        archive_document, archive_payload = _receipt_document(
            self.archive_receipt,
            "archive_raw_export",
        )
        observation_document, observation_payload = _receipt_document(
            self.observation_receipt,
            "append_observation",
        )
        timeline_document, timeline_payload = _receipt_document(
            self.timeline_receipt,
            "register_timeline",
        )
        if (
            archive_payload.get("evidence_id") != self.evidence.evidence_id
            or archive_payload.get("source_sha256")
            != self.evidence.source_sha256
            or observation_payload.get("observation_id")
            != self.observation.observation_id
            or observation_payload.get("raw_evidence_id")
            != self.evidence.evidence_id
            or timeline_payload.get("timeline_id")
            != self.timeline.timeline_id
            or not (
                archive_document["sequence"]
                < observation_document["sequence"]
                < timeline_document["sequence"]
            )
        ):
            raise ValueError(
                "coordinator result receipts do not bind the typed pipeline"
            )

        if (self.intent is None) != (self.intent_receipt is None):
            raise ValueError(
                "coordinator intent and receipt presence must agree"
            )
        if self.intent is not None:
            if (
                not isinstance(self.intent, FollowUpIntent)
                or self.intent.timeline != self.timeline
            ):
                raise ValueError(
                    "coordinator intent differs from the registered timeline"
                )
            self.intent.__post_init__()
            intent_document, intent_payload = _receipt_document(
                self.intent_receipt,
                "register_follow_up_intent",
            )
            if (
                intent_payload.get("timeline_id")
                != self.timeline.timeline_id
                or intent_payload.get("idempotency_key")
                != self.intent.idempotency_key
                or intent_payload.get("intent_sha256")
                != self.intent.intent_sha256
                or timeline_document["sequence"]
                >= intent_document["sequence"]
            ):
                raise ValueError(
                    "coordinator intent receipt differs from exact content"
                )

        if (
            self.policy_sha256 != COORDINATOR_POLICY_SHA256
            or self.partial_progress != "truthful_receipted_steps"
            or self.atomicity_across_steps != "absent"
            or self.durable_read_api != "absent"
            or self.follow_up_reference_hashes
            != "caller_supplied_structural_references"
            or self.connector_authority != "withheld"
            or self.send_authority != "withheld"
            or self.objective_satisfied is not False
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.external_action_capability is not False
        ):
            raise ValueError(
                "coordinator result cannot connect, send, satisfy, or certify"
            )


def _verify_typed_history(
    *,
    application_id: str,
    job_key: str,
    prior_observations: tuple[StatusObservation, ...],
    censored_silence: tuple[CensoredSilence, ...],
) -> None:
    if not isinstance(prior_observations, tuple) or not all(
        isinstance(row, StatusObservation) for row in prior_observations
    ):
        raise TypeError(
            "coordinator prior observations must be a typed tuple"
        )
    if not isinstance(censored_silence, tuple) or not all(
        isinstance(row, CensoredSilence) for row in censored_silence
    ):
        raise TypeError(
            "coordinator censored silence must be a typed tuple"
        )
    for row in prior_observations:
        row.verify()
        if row.application_id != application_id or row.job_key != job_key:
            raise ValueError(
                "prior observation belongs to a different application"
            )
    for row in censored_silence:
        row.__post_init__()
        if row.application_id != application_id or row.job_key != job_key:
            raise ValueError(
                "censored silence belongs to a different application"
            )


def ingest_local_export(
    store: StatusEvidenceStore,
    *,
    application_id: str,
    job_key: str,
    source_kind: str,
    source_record_id: str,
    raw_export_bytes: bytes,
    observed_at: datetime,
    explicit_status_code: str,
    prior_observations: tuple[StatusObservation, ...],
    censored_silence: tuple[CensoredSilence, ...] = (),
    follow_up: FollowUpRegistrationRequest | None = None,
) -> LocalExportIngestionResult:
    """Compile and durably register one exact local-export observation.

    Store calls are deliberately non-atomic across steps.  A raised exception
    never hides or compensates for a successfully receipted prefix.
    """
    if not isinstance(store, StatusEvidenceStore):
        raise TypeError(
            "local export ingestion requires StatusEvidenceStore"
        )
    if (
        store.identity.contract_sha256
        != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
    ):
        raise ValueError("status store binds a different contract")
    if not isinstance(explicit_status_code, str):
        raise ValueError("explicit status code must be text")
    if follow_up is not None and not isinstance(
        follow_up,
        FollowUpRegistrationRequest,
    ):
        raise TypeError(
            "follow-up registration requires a typed request"
        )
    _verify_typed_history(
        application_id=application_id,
        job_key=job_key,
        prior_observations=prior_observations,
        censored_silence=censored_silence,
    )

    contract = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT
    evidence = compile_local_export_evidence(
        contract,
        application_id=application_id,
        job_key=job_key,
        source_kind=source_kind,
        source_record_id=source_record_id,
        raw_export_bytes=raw_export_bytes,
        observed_at=observed_at,
    )
    archive_receipt = store.archive_raw_export(
        evidence,
        raw_export_bytes,
    )
    observation = classify_status_evidence(
        contract,
        evidence,
        explicit_status_code=explicit_status_code,
    )
    observation_receipt = store.append_observation(observation)
    timeline = compile_status_timeline(
        contract,
        application_id=application_id,
        job_key=job_key,
        observations=prior_observations + (observation,),
        censored_silence=censored_silence,
    )
    timeline_receipt = store.register_timeline(timeline)

    intent: FollowUpIntent | None = None
    intent_receipt: StatusEvidenceStoreReceipt | None = None
    if follow_up is not None:
        intent = compile_follow_up_intent(
            contract,
            timeline,
            released_application_sha256=(
                follow_up.released_application_sha256
            ),
            draft_sha256=follow_up.draft_sha256,
        )
        intent_receipt = store.register_follow_up_intent(intent)

    return LocalExportIngestionResult(
        evidence=evidence,
        observation=observation,
        timeline=timeline,
        archive_receipt=archive_receipt,
        observation_receipt=observation_receipt,
        timeline_receipt=timeline_receipt,
        intent=intent,
        intent_receipt=intent_receipt,
    )
