"""Authenticated production-time entrypoint for deterministic Market handoffs.

This is the only production-facing constructor. It obtains current time from
the installed deployment-owned witness and passes that instant to the internal
deterministic builder only for freshness evaluation. It issues no release token
and grants no submission authority.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import (
    PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
    ProductionHandoffDeployment,
    ProductionHandoffReceipt,
    _build_production_handoff_from_authenticated_time,
)

from .current_time import installed_production_current_time_witness, obtain_current_time


def run_production_handoff(
    *,
    deployment: ProductionHandoffDeployment,
    profile_id: str,
    track: str,
    source_job_key: str,
) -> ProductionHandoffReceipt:
    """Build a preparation handoff using authenticated production time."""

    subject = {
        "candidate_authority_sha256": PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "data_home": str(deployment.data_home.absolute()),
        "output_root": str(deployment.output_root.absolute()),
        "profile_id": profile_id,
        "repository_root": str(deployment.repository_root.absolute()),
        "schema_version": "jaa.production-handoff-freshness-subject.v1",
        "source_job_key": source_job_key,
        "track": track,
    }
    subject_sha256 = hashlib.sha256(canonical_json_bytes(subject)).hexdigest()
    evidence = obtain_current_time(
        installed_production_current_time_witness(),
        environment="production",
        purpose="production_handoff_freshness",
        subject_sha256=subject_sha256,
        maximum_clock_skew_seconds=300,
    )
    evaluated_at = datetime.fromisoformat(
        evidence.evaluated_at[:-1] + "+00:00"
        if evidence.evaluated_at.endswith("Z")
        else evidence.evaluated_at
    ).astimezone(timezone.utc)
    return _build_production_handoff_from_authenticated_time(
        deployment=deployment,
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        freshness_time=evaluated_at,
    )


__all__ = ["run_production_handoff"]
