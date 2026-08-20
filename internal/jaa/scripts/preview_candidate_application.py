#!/usr/bin/env python3
"""Generate, assure, semantically review and archive one application preview."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.application_artifacts import publish_application_artifacts  # noqa: E402
from career_automation.application_preview import ApplicationPreviewArchive  # noqa: E402
from career_automation.application_sanity_review import (  # noqa: E402
    ApplicationSanityReviewError,
    package_from_application,
    review_application_package,
)
from cv_generation.service import (  # noqa: E402
    build_candidate_application_package,
)
from career_automation.candidate_contact_authority import (  # noqa: E402
    load_candidate_contact_authority,
)
from career_automation.evidence_matching import canonical_json  # noqa: E402
from career_automation.external_document_assurance import (  # noqa: E402
    IntendedVacancy,
    assert_application_artifacts,
)
from llm.client import LLMClient, make_backend  # noqa: E402


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _canonical_file(
    path: Path,
    *,
    content_addressed_name: bool = False,
    require_canonical_json: bool = True,
) -> tuple[dict[str, object], bytes, str]:
    value = path.read_bytes()
    document = json.loads(value)
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    if require_canonical_json and value != _json_bytes(document):
        raise ValueError(f"{path} is not canonical JSON")
    digest = hashlib.sha256(value).hexdigest()
    if content_addressed_name and path.stem != digest:
        raise ValueError(f"{path} is not named by its exact hash")
    return document, value, digest


def _select_decision(
    authority: dict[str, object],
    job_key: str | None,
    *,
    live_job_keys: frozenset[str],
) -> dict[str, object]:
    rows = authority.get("decisions")
    if not isinstance(rows, list):
        raise ValueError("candidate authority lacks decisions")
    viable: list[tuple[Decimal, int, str, dict[str, object]]] = []
    for envelope in rows:
        if (
            not isinstance(envelope, dict)
            or not isinstance(envelope.get("receipt"), dict)
        ):
            raise ValueError("candidate decision envelope is malformed")
        receipt = dict(envelope["receipt"])
        matrix = receipt.get("evidence_matrix")
        matched = isinstance(matrix, list) and any(
            isinstance(row, dict)
            and row.get("status") == "matched"
            and row.get("evidence_ids")
            for row in matrix
        )
        if (
            receipt.get("decision") == "eligible"
            and matched
            and receipt.get("job_key") in live_job_keys
        ):
            try:
                fit = Decimal(str(receipt["fit"]))
            except (KeyError, InvalidOperation, ValueError) as exc:
                raise ValueError("candidate decision has an invalid fit value") from exc
            if not fit.is_finite() or not Decimal("0") <= fit <= Decimal("1"):
                raise ValueError("candidate decision fit is outside zero to one")
            matched_essential = sum(
                1
                for row in matrix
                if isinstance(row, dict)
                and row.get("classification") == "essential"
                and row.get("status") == "matched"
                and row.get("evidence_ids")
            )
            viable.append(
                (fit, matched_essential, str(receipt["job_key"]), receipt)
            )
    if job_key is not None:
        viable = [row for row in viable if row[2] == job_key]
    viable.sort(key=lambda row: (-row[0], -row[1], row[2]))
    if not viable:
        raise ValueError("no requested viable candidate decision exists")
    return viable[0][3]


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("live discovery observed_at is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("live discovery observed_at is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError("live discovery observed_at is not UTC")
    return parsed


def _live_vacancy_index(
    discovery: dict[str, object],
    *,
    now: datetime,
    max_age: timedelta,
) -> dict[str, dict[str, object]]:
    """Validate one read-only discovery and return only independently live jobs."""
    if discovery.get("schema_version") != "jaa.greenhouse-live-discovery.v2":
        raise ValueError("unsupported live discovery schema")
    if now.tzinfo is None:
        raise ValueError("liveness clock must be timezone-aware")
    observed_at = _parse_utc(discovery.get("observed_at"))
    age = now.astimezone(timezone.utc) - observed_at
    if age < timedelta(0) or age > max_age:
        raise ValueError("live discovery is outside the permitted freshness window")
    if discovery.get("interaction") != {
        "fields_filled": 0,
        "files_uploaded": 0,
        "submit_clicks": 0,
    }:
        raise ValueError("live discovery was not read-only")
    observations = discovery.get("observations")
    pending = discovery.get("live_pending_eligibility")
    if not isinstance(observations, list) or not isinstance(pending, list):
        raise ValueError("live discovery vacancy collections are malformed")
    observed: dict[str, dict[str, object]] = {}
    for row in observations:
        if not isinstance(row, dict) or not isinstance(row.get("job_key"), str):
            raise ValueError("live discovery observation is malformed")
        key = row["job_key"]
        if key in observed:
            raise ValueError("live discovery contains duplicate observations")
        verdict = row.get("verdict")
        if isinstance(verdict, dict) and verdict.get("live") is True:
            observed[key] = row
    result: dict[str, dict[str, object]] = {}
    for row in pending:
        if not isinstance(row, dict) or not isinstance(row.get("job_key"), str):
            raise ValueError("live pending vacancy is malformed")
        key = row["job_key"]
        if key in result or key not in observed:
            raise ValueError("live pending vacancy lacks one live observation")
        observation = observed[key]
        bindings = (
            ("role_title", "role_title"),
            ("company_name", "company_name"),
            ("source_url", "requested_url"),
        )
        if any(row.get(left) != observation.get(right) for left, right in bindings):
            raise ValueError("live vacancy identity differs from its observation")
        result[key] = row
    if not result:
        raise ValueError("live discovery contains no live vacancies")
    return result


def _assert_live_decision_binding(
    decision: dict[str, object], live_vacancy: dict[str, object]
) -> None:
    for field in ("job_key", "role_title", "company_name", "source_url"):
        if decision.get(field) != live_vacancy.get(field):
            raise ValueError(f"candidate decision differs from live vacancy {field}")


def _repository_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-authority", type=Path, required=True)
    parser.add_argument("--contact-authority", type=Path, required=True)
    parser.add_argument("--approved-evidence", type=Path, required=True)
    parser.add_argument("--live-discovery", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--job-key")
    parser.add_argument(
        "--backend",
        choices=("codex_cli", "claude_cli"),
        default="codex_cli",
    )
    parser.add_argument("--model", default="")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--max-liveness-age-hours", type=float, default=24)
    args = parser.parse_args()

    authority, authority_value, authority_sha256 = _canonical_file(
        args.candidate_authority,
        content_addressed_name=True,
    )
    _, evidence_value, evidence_sha256 = _canonical_file(
        args.approved_evidence,
        require_canonical_json=False,
    )
    if not 0 < args.max_liveness_age_hours <= 24:
        parser.error("--max-liveness-age-hours must be above zero and at most 24")
    live_document, live_value, live_sha256 = _canonical_file(args.live_discovery)
    live_index = _live_vacancy_index(
        live_document,
        now=datetime.now(timezone.utc),
        max_age=timedelta(hours=args.max_liveness_age_hours),
    )
    decision = _select_decision(
        authority,
        args.job_key,
        live_job_keys=frozenset(live_index),
    )
    _assert_live_decision_binding(decision, live_index[str(decision["job_key"])])
    projection = authority.get("candidate_projection")
    if not isinstance(projection, dict):
        raise ValueError("candidate authority projection is malformed")
    source_hashes = decision.get("source_hashes")
    if (
        not isinstance(source_hashes, dict)
        or evidence_sha256 != source_hashes.get("approved_evidence")
    ):
        raise ValueError("approved evidence differs from candidate decision")
    contact_document, contact_value, contact_file_sha256 = _canonical_file(
        args.contact_authority,
    )
    contact_authority = load_candidate_contact_authority(
        args.contact_authority,
        repository_root=ROOT,
    )
    contact_sha256 = contact_authority.authority_sha256
    if (
        contact_document.get("authority_sha256") != contact_sha256
        or args.contact_authority.stem != contact_sha256
    ):
        raise ValueError("loaded contact authority differs from exact file")
    vacancy = IntendedVacancy(
        str(decision["job_key"]),
        str(decision["vacancy_sha256"]),
        str(decision["role_title"]),
        str(decision["company_name"]),
    )
    archive = ApplicationPreviewArchive(
        root=args.archive_root,
        repository_root=ROOT,
        vacancy=vacancy,
        candidate_authority_sha256=authority_sha256,
        contact_authority_sha256=contact_sha256,
    )
    archive.add_artifact(
        role="candidate.authority",
        value=authority_value,
        media_type="application/json",
        disposition="approved",
    )
    archive.add_artifact(
        role="candidate.contact_authority",
        value=contact_value,
        media_type="application/json",
        disposition="approved",
    )
    archive.add_artifact(
        role="evidence.approved_packet",
        value=evidence_value,
        media_type="application/json",
        disposition="approved",
    )
    archive.add_artifact(
        role="vacancy.live_discovery",
        value=live_value,
        media_type="application/json",
        disposition="observed",
    )
    try:
        package = build_candidate_application_package(
            decision_receipt=decision,
            candidate_projection=projection,
            job_key=str(decision["job_key"]),
            vacancy_sha256=str(decision["vacancy_sha256"]),
            source_url=str(decision["source_url"]),
            role_title=str(decision["role_title"]),
            company_name=str(decision["company_name"]),
            contact=contact_authority.contact,
            approved_evidence_path=args.approved_evidence,
            revision_writer=archive.revision_writer,
        )
        archive.add_artifact(
            role="document.cv.extracted_text",
            value=package.artifacts.cv_pdf.extracted_text.encode(),
            media_type="text/plain",
            disposition="approved",
        )
        archive.add_artifact(
            role="document.cover_letter.extracted_text",
            value=package.artifacts.cover_letter_pdf.extracted_text.encode(),
            media_type="text/plain",
            disposition="approved",
        )
        publication = publish_application_artifacts(
            package.source,
            package.artifacts,
            root=(
                args.archive_root
                / "application-previews"
                / "published-artifact-sets"
            ),
            repository_root=ROOT,
        )
        archive.add_artifact(
            role="publication.receipt",
            value=_json_bytes(publication.document()),
            media_type="application/json",
            disposition="approved",
        )
        deterministic = assert_application_artifacts(
            cv_pdf_bytes=package.artifacts.cv_pdf.pdf_bytes,
            cover_letter_pdf_bytes=package.artifacts.cover_letter_pdf.pdf_bytes,
            answers_text=package.artifacts.editable.answers_text,
            intended_vacancy=vacancy,
        )
        archive.add_artifact(
            role="assurance.cv.receipt",
            value=_json_bytes(deterministic[0].document()),
            media_type="application/json",
            disposition="approved",
        )
        archive.add_artifact(
            role="assurance.cover_letter.receipt",
            value=_json_bytes(deterministic[1].document()),
            media_type="application/json",
            disposition="approved",
        )
        backend_config: dict[str, object] = {
            "backend": args.backend,
            "cli_timeout_seconds": args.timeout,
        }
        if args.model:
            backend_config[
                "model" if args.backend == "claude_cli" else "codex_model"
            ] = args.model
        backend = make_backend(backend_config)
        client = LLMClient(
            backend=backend,
            model=args.model or "provider-default",
            temperature=0,
            max_retries=1,
            cache_enabled=False,
            cache_dir=(
                args.archive_root
                / "application-previews"
                / "review-cache"
                / archive.preview_id
            ),
            usage_log=(
                args.archive_root
                / "application-previews"
                / "review-usage.jsonl"
            ),
        )
        sanity_package = package_from_application(
            source=package.source,
            artifacts=package.artifacts,
            questions=None,
            vacancy_requirements=package.vacancy_requirements,
        )
        sanity = review_application_package(sanity_package, client=client)
        archive.add_artifact(
            role="assurance.semantic.receipt",
            value=_json_bytes(sanity.document()),
            media_type="application/json",
            disposition="approved",
        )
        archive.add_artifact(
            role="production.identity",
            value=_json_bytes(
                {
                    "repository_head": _repository_head(),
                    "candidate_authority_sha256": authority_sha256,
                    "contact_authority_sha256": contact_sha256,
                    "contact_authority_file_sha256": contact_file_sha256,
                    "live_discovery_sha256": live_sha256,
                    "semantic_backend": sanity.backend_identity,
                    "semantic_model": sanity.model_identity,
                }
            ),
            media_type="application/json",
            disposition="approved",
        )
        receipt = archive.finalize(status="ready")
    except ApplicationSanityReviewError as error:
        archive.add_artifact(
            role="assurance.semantic.block",
            value=_json_bytes({"code": error.code, "result": error.result}),
            media_type="application/json",
            disposition="rejected",
        )
        receipt = archive.finalize(status="blocked", reason_code=error.code)
    except Exception as error:
        archive.add_artifact(
            role="preview.failure",
            value=_json_bytes(
                {"error_type": type(error).__name__, "message": str(error)}
            ),
            media_type="application/json",
            disposition="rejected",
        )
        receipt = archive.finalize(
            status="error",
            reason_code=f"preview.{type(error).__name__}",
        )
    print(
        canonical_json(
            {
                **receipt.document(),
                "run_relative_path": str(archive.path.relative_to(archive.root)),
            }
        )
    )
    return 0 if receipt.status == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
