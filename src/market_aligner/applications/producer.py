"""Small, deterministic producer from persisted assessment state to JAA handoff v1."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from market_aligner.applications.handoff import HandoffEnvelope, encode_handoff_v1
from market_aligner.research.store import AssessmentStore


_MANIFEST_KEYS = {
    "assessment_receipt_sha256",
    "candidate_intent_sha256",
    "created_at",
    "eligibility",
    "employer_dossier_sha256",
    "evidence_ledger_sha256",
    "producer_commit_sha",
    "selection",
    "vacancy",
}


class HandoffProducerError(ValueError):
    """The persisted assessment and supplied evidence manifest cannot form a handoff."""


def _exact_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HandoffProducerError("handoff manifest must be an object")
    if set(value) != _MANIFEST_KEYS:
        missing = sorted(_MANIFEST_KEYS - set(value))
        extra = sorted(set(value) - _MANIFEST_KEYS)
        raise HandoffProducerError(
            f"handoff manifest keys differ; missing={missing}, extra={extra}"
        )
    return dict(value)


def produce_handoff(
    store: AssessmentStore,
    *,
    profile_id: str,
    profile_version: str,
    job_key: str,
    manifest: Mapping[str, Any],
) -> HandoffEnvelope:
    """Read one admitted score and compose its exact, hash-bound v1 wire document.

    The caller supplies evidence identities and vacancy facts, while every score,
    profile identity, opportunity decision, and selection-policy identity is read
    back from durable Market Aligner state.
    """

    inputs = _exact_manifest(manifest)
    row = store.assessment(profile_id, job_key)
    if row["opportunity_decision"] != "pass":
        raise HandoffProducerError("handoff requires a persisted opportunity-gate pass")
    if not isinstance(row["policy_hash"], str) or len(row["policy_hash"]) != 64:
        raise HandoffProducerError("persisted opportunity policy is not SHA-256-bound")
    if row["extraction_confidence"] is None:
        raise HandoffProducerError("handoff requires persisted extraction confidence")

    try:
        score = json.loads(row["score_payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise HandoffProducerError("persisted score payload is invalid") from exc
    if score.get("profile_id") != profile_id or score.get("job_key") != job_key:
        raise HandoffProducerError("persisted score identity differs from requested handoff")
    for score_key, row_key in (
        ("fit", "fit"),
        ("opportunity", "opportunity"),
        ("final", "final_score"),
    ):
        if float(score.get(score_key, -1)) != float(row[row_key]):
            raise HandoffProducerError(f"persisted {score_key} projection differs from its row")

    selection = inputs["selection"]
    if not isinstance(selection, Mapping):
        raise HandoffProducerError("selection manifest must be an object")
    if selection.get("selection_policy_sha256") != row["policy_hash"]:
        raise HandoffProducerError("selection policy differs from the persisted gate policy")

    vacancy = inputs["vacancy"]
    if not isinstance(vacancy, Mapping):
        raise HandoffProducerError("vacancy manifest must be an object")
    provenance = vacancy.get("provenance")
    if not isinstance(provenance, Mapping) or provenance.get("canonical_url") != row["url"]:
        raise HandoffProducerError("vacancy URL differs from the persisted assessment")
    if vacancy.get("role_title") != row["title"] or vacancy.get("company_name") != row["company"]:
        raise HandoffProducerError("vacancy title or company differs from the persisted assessment")

    payload = {
        "assessment": {
            "assessment_receipt_sha256": inputs["assessment_receipt_sha256"],
            "extraction_confidence": float(row["extraction_confidence"]),
            "final": float(row["final_score"]) / 100.0,
            "fit": float(row["fit"]),
            "fit_components": score["fit_subscores"],
            "fit_status": row["fit_status"],
            "opportunity": float(row["opportunity"]),
            "opportunity_components": score["opportunity_subscores"],
            "scoring_parameters_sha256": score["parameters_hash"],
        },
        "candidate_intent_sha256": inputs["candidate_intent_sha256"],
        "created_at": inputs["created_at"],
        "eligibility": inputs["eligibility"],
        "employer_dossier_sha256": inputs["employer_dossier_sha256"],
        "evidence_ledger_sha256": inputs["evidence_ledger_sha256"],
        "job_key": job_key,
        "producer": {
            "commit_sha": inputs["producer_commit_sha"],
            "product": "market-aligner",
        },
        "profile_id": profile_id,
        "profile_version": profile_version,
        "selection": selection,
        "vacancy": vacancy,
    }
    return encode_handoff_v1(payload)


def write_handoff(path: str | Path, handoff: HandoffEnvelope) -> None:
    """Atomically write the exact wire bytes to the explicitly selected output."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(handoff.exact_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
