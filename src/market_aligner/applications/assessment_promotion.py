"""Deterministic promotion from current processing evidence into handoff state."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from market_aligner.research.store import AssessmentStore
from market_aligner.state.vacancies import (
    LEGACY_PROCESSING_CONFIG_SHA256,
    JobDatabase,
)


def _bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _hash(value: object) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


class AssessmentPromotionError(ValueError):
    pass


@dataclass(frozen=True)
class AssessmentPromotion:
    profile_id: str
    job_key: str
    policy_sha256: str
    receipt_sha256: str
    receipt_path: Path
    created: bool


def _receipt(path: Path) -> tuple[dict[str, object], bytes, str]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise AssessmentPromotionError("processing receipt must be an absolute regular file")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssessmentPromotionError("processing receipt is invalid JSON") from exc
    if not isinstance(document, dict) or raw != _bytes(document):
        raise AssessmentPromotionError("processing receipt is not canonical JSON")
    claimed = document.get("receipt_sha256")
    body = dict(document)
    body.pop("receipt_sha256", None)
    digest = _hash(body)
    if claimed != digest or path.name != f"{digest}.json":
        raise AssessmentPromotionError("processing receipt identity is invalid")
    if document.get("schema_version") != "market-aligner.processing-run-receipt.v1":
        raise AssessmentPromotionError("processing receipt schema is unsupported")
    return document, raw, digest


def _atomic_exact(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != value:
            raise AssessmentPromotionError("promotion receipt replay differs")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def promote_current_processing_assessment(
    *,
    jobs: JobDatabase,
    assessments: AssessmentStore,
    processing_receipt_path: Path,
    profile_id: str,
    track: str,
    job_key: str,
    receipt_root: Path,
) -> AssessmentPromotion:
    """Promote one exact included result; stale or non-current state fails closed."""

    run, run_bytes, run_sha = _receipt(processing_receipt_path)
    if (
        run.get("profile_id") != profile_id
        or run.get("track") != track
        or run.get("application_authority") is not False
        or run.get("authority_scope") != "processing_only"
    ):
        raise AssessmentPromotionError("processing receipt authority differs")
    authority = run.get("evidence_authority_sha256")
    config = run.get("config_sha256")
    if (
        not isinstance(authority, str)
        or len(authority) != 64
        or not isinstance(config, str)
        or len(config) != 64
        or config == LEGACY_PROCESSING_CONFIG_SHA256
    ):
        raise AssessmentPromotionError("processing receipt uses stale or legacy identity")
    scope = run.get("scope")
    if not isinstance(scope, dict) or set(scope) != {
        "exclude_boards",
        "include_boards",
        "max_total",
    }:
        raise AssessmentPromotionError("processing receipt scope is invalid")
    current_rows = jobs.completed_processing(
        profile_id=profile_id,
        track=track,
        authority_sha256=authority,
        processing_config_sha256=config,
        include_boards=scope["include_boards"],
        exclude_boards=scope["exclude_boards"],
        max_total=scope["max_total"],
    )
    if _hash(current_rows) != run.get("state_sha256"):
        raise AssessmentPromotionError("processing receipt is stale for current state")
    candidates = []
    for row in current_rows:
        if not isinstance(row, dict) or not isinstance(row.get("vacancy"), dict):
            continue
        candidate_vacancy = row["vacancy"]
        candidate_key = candidate_vacancy.get("key") or (
            f"{candidate_vacancy.get('board')}:{candidate_vacancy.get('job_id')}"
        )
        if candidate_key == job_key:
            candidates.append(row)
    if len(candidates) != 1:
        raise AssessmentPromotionError("job is absent or ambiguous in current processing receipt")
    result = candidates[0]
    viability = result.get("viability")
    first_job = result.get("first_job_scope")
    geography = result.get("geographic_preference")
    opportunity = result.get("opportunity_axes")
    score = result.get("score")
    vacancy = result.get("vacancy")
    if (
        result.get("included") is not True
        or result.get("processing_config_sha256") != config
        or not isinstance(viability, dict)
        or viability.get("decision") != "include"
        or not isinstance(first_job, dict)
        or first_job.get("decision") != "include"
        or not isinstance(geography, dict)
        or not isinstance(opportunity, dict)
        or not isinstance(score, dict)
        or not isinstance(vacancy, dict)
    ):
        raise AssessmentPromotionError("processing result is rejected, parked or malformed")
    if (
        first_job.get("policy_sha256")
        != run.get("first_job_scope_policy_sha256")
        or geography.get("policy_sha256")
        != run.get("geographic_preference_policy_sha256")
        or opportunity.get("policy_sha256")
        != run.get("opportunity_policy_sha256")
    ):
        raise AssessmentPromotionError("processing result policy bindings differ")
    if score.get("profile_id") != profile_id or score.get("job_key") != job_key:
        raise AssessmentPromotionError("processing score identity differs")
    with jobs.connect() as connection:
        current = connection.execute(
            """SELECT q.source_content_sha256,q.result_json,p.content_hash
               FROM processing_jobs q JOIN postings p ON p.key=q.job_key
               WHERE q.profile_id=? AND q.track=? AND q.job_key=?
                 AND q.authority_sha256=? AND q.processing_config_sha256=?
                 AND q.status='completed' AND q.result_json IS NOT NULL
                 AND p.fetch_status='fetched' AND p.content_hash=q.source_content_sha256""",
            (profile_id, track, job_key, authority, config),
        ).fetchall()
    if len(current) != 1 or json.loads(current[0][1]) != result:
        raise AssessmentPromotionError("processing row is not current exact source state")
    source_content = str(current[0][0])
    result_sha = _hash(result)
    assessment = assessments.assessment(profile_id, job_key)
    try:
        stored_score = json.loads(assessment["score_payload_json"])
    except json.JSONDecodeError as exc:
        raise AssessmentPromotionError("assessment score payload is invalid") from exc
    score_keys = {
        "final",
        "fit",
        "fit_status",
        "fit_subscores",
        "job_key",
        "opportunity",
        "opportunity_subscores",
        "parameters_hash",
        "profile_id",
        "track",
    }
    if (
        any(stored_score.get(key) != score.get(key) for key in score_keys)
        or assessment["url"] != vacancy.get("url")
        or assessment["title"] != vacancy.get("title")
        or assessment["company"] != vacancy.get("company")
        or assessment["extraction_confidence"]
        != vacancy.get("extraction_confidence")
    ):
        raise AssessmentPromotionError("assessment differs from processing result")
    score_input = {
        "final": score.get("final"),
        "fit": score.get("fit"),
        "fit_status": score.get("fit_status"),
        "fit_subscores": score.get("fit_subscores"),
        "opportunity": score.get("opportunity"),
        "opportunity_subscores": score.get("opportunity_subscores"),
        "parameters_hash": score.get("parameters_hash"),
    }
    policy = {
        "first_job_scope_policy_sha256": run.get(
            "first_job_scope_policy_sha256"
        ),
        "geographic_preference_policy_sha256": run.get(
            "geographic_preference_policy_sha256"
        ),
        "opportunity_policy_sha256": run.get("opportunity_policy_sha256"),
        "processing_config_sha256": config,
        "schema_version": "market-aligner.selection-policy.v1",
    }
    if any(
        not isinstance(value, str) or len(value) != 64
        for key, value in policy.items()
        if key != "schema_version"
    ):
        raise AssessmentPromotionError("processing policy identities are incomplete")
    policy_sha = _hash(policy)
    binding = {
        "evidence_authority_sha256": authority,
        "first_job_scope": first_job,
        "fit_input_sha256": _hash(score_input),
        "geographic_preference": geography,
        "job_key": job_key,
        "opportunity_input_sha256": _hash(opportunity),
        "processing_config_sha256": config,
        "processing_receipt_sha256": run_sha,
        "processing_result_sha256": result_sha,
        "profile_id": profile_id,
        "schema_version": "market-aligner.assessment-promotion-binding.v1",
        "source_content_sha256": source_content,
        "track": track,
        "viability": viability,
    }
    binding_sha = _hash(binding)
    promotion_body = {
        "binding": binding,
        "binding_sha256": binding_sha,
        "decision": "pass",
        "evidence_authority_sha256": authority,
        "job_key": job_key,
        "policy": policy,
        "policy_sha256": policy_sha,
        "processing_receipt_bytes_sha256": hashlib.sha256(run_bytes).hexdigest(),
        "profile_id": profile_id,
        "schema_version": "market-aligner.assessment-promotion-receipt.v1",
        "score_payload_hash": assessment["score_payload_hash"],
    }
    promotion_sha = _hash(promotion_body)
    promotion = {**promotion_body, "receipt_sha256": promotion_sha}
    promotion_bytes = _bytes(promotion)
    created = assessments.promote_processing_gate(
        profile_id=profile_id,
        job_key=job_key,
        score=score,
        policy_hash=policy_sha,
        processing_receipt_sha256=run_sha,
        processing_result_sha256=result_sha,
        source_content_sha256=source_content,
        authority_sha256=authority,
        processing_config_sha256=config,
        track=track,
        receipt_bytes=promotion_bytes,
        receipt_sha256=promotion_sha,
    )
    receipt_path = receipt_root.resolve() / f"{promotion_sha}.json"
    _atomic_exact(receipt_path, promotion_bytes)
    return AssessmentPromotion(
        profile_id,
        job_key,
        policy_sha,
        promotion_sha,
        receipt_path,
        created,
    )


__all__ = [
    "AssessmentPromotion",
    "AssessmentPromotionError",
    "promote_current_processing_assessment",
]
