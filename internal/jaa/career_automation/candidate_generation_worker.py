"""Exact-clean isolated worker for sink-first candidate package generation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import sys
import traceback
from pathlib import Path
from typing import BinaryIO

from .application_compiler import (
    ApplicationSource,
    CandidateContact,
    verify_application_source,
)
from .candidate_application_factory import CandidateApplicationPackage
from cv_generation.service import build_candidate_application_package
from .evidence_matching import canonical_json


GENERATION_OUTPUT_FD_ENV = "JAA_GENERATION_OUTPUT_FD"
_revision_stream: BinaryIO | None = None


def _write(document: dict[str, object]) -> None:
    sys.stdout.write(canonical_json(document) + "\n")
    sys.stdout.flush()


def _revision_writer(**arguments: object) -> None:
    value = arguments.get("value")
    if not isinstance(value, bytes):
        raise TypeError("isolated generation revision must contain exact bytes")
    if _revision_stream is None:
        raise RuntimeError("isolated generation sink is unavailable")
    document = {
        "kind": "revision",
        "role": arguments["role"],
        "media_type": arguments["media_type"],
        "prior_sha256": arguments.get("prior_sha256"),
        "approved": arguments.get("approved", True),
        "rejection_codes": list(arguments.get("rejection_codes", ())),
        "value_base64": base64.b64encode(value).decode("ascii"),
    }
    _revision_stream.write((canonical_json(document) + "\n").encode())
    _revision_stream.flush()


def _generate_from_request() -> int:
    request = json.loads(sys.stdin.buffer.read())
    if not isinstance(request, dict):
        raise ValueError("isolated generation request is malformed")
    contact_document = request.pop("contact")
    approved_evidence_path = request.pop("approved_evidence_path", None)
    current_application_id = request.pop("current_runtime_application_id", None)
    current_pre_review_kwargs = request.pop("current_runtime_pre_review_kwargs", None)
    if not isinstance(contact_document, dict):
        raise ValueError("isolated generation contact is malformed")
    contact = CandidateContact(**contact_document)
    current_runtime = (
        current_application_id is not None or current_pre_review_kwargs is not None
    )
    if current_runtime:
        expected_keys = {
            "current_runtime_config_path",
            "current_runtime_config_sha256",
            "current_runtime_private_root",
            "current_recovery_manifest_relative_path",
        }
        if (
            type(current_application_id) is not str
            or len(current_application_id) != 68
            or not current_application_id.startswith("app_")
            or any(
                character not in "0123456789abcdef"
                for character in current_application_id[4:]
            )
            or type(current_pre_review_kwargs) is not dict
            or set(current_pre_review_kwargs) != expected_keys
            or any(
                type(value) is not str or not value
                for value in current_pre_review_kwargs.values()
            )
            or approved_evidence_path is not None
        ):
            raise ValueError("current pre-review generation request is incomplete")
        _generate_current_runtime_package(
            request=request,
            contact=contact,
            application_id=current_application_id,
            pre_review_kwargs=current_pre_review_kwargs,
        )
        return 0
    if approved_evidence_path is not None:
        request["approved_evidence_path"] = Path(str(approved_evidence_path))
    package = build_candidate_application_package(
        **request,
        contact=contact,
        revision_writer=_revision_writer,
    )
    package_pickle = pickle.dumps(package, protocol=5)
    _revision_writer(
        role="generation.package_pickle",
        value=package_pickle,
        media_type="application/octet-stream",
    )
    _write(
        {
            "kind": "result",
            "package_pickle_sha256": hashlib.sha256(package_pickle).hexdigest(),
        }
    )
    return 0


def _generate_current_runtime_package(
    *,
    request: dict[str, object],
    contact: CandidateContact,
    application_id: str,
    pre_review_kwargs: dict[str, str],
) -> None:
    from cv_generation.constraints import CandidateSourcePolicyReceipt
    from .market_aligner_preparation import MarketApplicationPreparation
    from .production_preparation_runner import run_production_market_pre_review
    from .rendering import (
        render_editable_text,
        verify_application_artifacts,
    )

    preparation = run_production_market_pre_review(
        application_id=application_id,
        **pre_review_kwargs,
    )
    if (
        type(preparation) is not MarketApplicationPreparation
        or preparation.release_authority is not False
        or preparation.review_status != "not_performed"
        or type(preparation.package) is not CandidateApplicationPackage
        or type(preparation.initial_constraint_receipt)
        is not CandidateSourcePolicyReceipt
    ):
        raise ValueError("current pre-review returned an invalid package")
    package = preparation.package
    materialized_source = package.materialized_source
    source = package.source
    artifacts = package.artifacts
    constraint_receipt = preparation.initial_constraint_receipt
    if (
        type(source) is not ApplicationSource
        or type(materialized_source) is not ApplicationSource
        or package.source_policy_receipt != constraint_receipt
        or type(package.vacancy_requirements) is not tuple
        or any(type(value) is not str for value in package.vacancy_requirements)
        or type(request.get("job_key")) is not str
        or type(request.get("vacancy_sha256")) is not str
        or type(request.get("source_url")) is not str
        or type(request.get("role_title")) is not str
        or type(request.get("company_name")) is not str
        or source.job_key != request["job_key"]
        or source.vacancy_sha256 != request["vacancy_sha256"]
        or source.role_title != request["role_title"]
        or source.company_name != request["company_name"]
        or source.contact != contact
        or materialized_source.job_key != source.job_key
        or materialized_source.vacancy_sha256 != source.vacancy_sha256
        or materialized_source.vacancy_source_identity
        != source.vacancy_source_identity
        or materialized_source.role_title != source.role_title
        or materialized_source.company_name != source.company_name
        or materialized_source.contact != source.contact
        or artifacts.source_id != source.source_id
        or constraint_receipt.source_id != source.source_id
        or constraint_receipt.cv_sha256 != artifacts.editable.cv_sha256
        or constraint_receipt.passed is not True
        or constraint_receipt.release_authority is not False
    ):
        raise ValueError("current pre-review package binding differs")
    verify_application_source(materialized_source)
    verify_application_source(source)
    verify_application_artifacts(artifacts)
    constraint_receipt.__post_init__()
    if render_editable_text(source) != artifacts.editable:
        raise ValueError("current pre-review artifacts differ from prepared source")

    _revision_writer(
        role="generation.inputs",
        value=(
            canonical_json(
                {
                    "application_id": application_id,
                    "company_name": source.company_name,
                    "current_recovery_manifest_relative_path": (
                        pre_review_kwargs[
                            "current_recovery_manifest_relative_path"
                        ]
                    ),
                    "current_runtime_config_sha256": pre_review_kwargs[
                        "current_runtime_config_sha256"
                    ],
                    "environment": "current_runtime",
                    "job_key": source.job_key,
                    "materialized_source_id": materialized_source.source_id,
                    "materialized_source_sha256": (
                        materialized_source.content_sha256
                    ),
                    "preparation_id": preparation.preparation_id,
                    "preparation_orchestration_sha256": (
                        preparation.orchestration_sha256
                    ),
                    "preparation_receipt_sha256": preparation.receipt_sha256,
                    "release_authority": False,
                    "review_status": "not_performed",
                    "role_title": source.role_title,
                    "schema_version": "jaa.current-runtime-generation-inputs.v1",
                    "source_sha256": source.content_sha256,
                    "source_url": request["source_url"],
                    "vacancy_source_identity": source.vacancy_source_identity,
                    "vacancy_sha256": source.vacancy_sha256,
                }
            )
            + "\n"
        ).encode(),
        media_type="application/json",
    )
    _revision_writer(
        role="document.source_inputs",
        value=(canonical_json(source.document()) + "\n").encode(),
        media_type="application/json",
    )
    _revision_writer(
        role="document.cv.constraints",
        value=(canonical_json(constraint_receipt.document()) + "\n").encode(),
        media_type="application/json",
    )
    for role, value, media_type in (
        ("document.cv.source", artifacts.editable.cv_text.encode(), "text/plain"),
        ("document.cv.final_pdf", artifacts.cv_pdf.pdf_bytes, "application/pdf"),
        (
            "document.cover_letter.source",
            artifacts.editable.cover_letter_text.encode(),
            "text/plain",
        ),
        (
            "document.cover_letter.final_pdf",
            artifacts.cover_letter_pdf.pdf_bytes,
            "application/pdf",
        ),
        ("form.answers", artifacts.editable.answers_text.encode(), "text/plain"),
    ):
        _revision_writer(role=role, value=value, media_type=media_type)
    package_pickle = pickle.dumps(package, protocol=5)
    _revision_writer(
        role="generation.package_pickle",
        value=package_pickle,
        media_type="application/octet-stream",
    )
    _write(
        {
            "kind": "result",
            "package_pickle_sha256": hashlib.sha256(package_pickle).hexdigest(),
        }
    )


def main() -> int:
    global _revision_stream
    binding = os.environ.get(GENERATION_OUTPUT_FD_ENV)
    if binding is None or not binding.isascii() or not binding.isdecimal():
        _write({"code": "OUTPUT_BINDING_ABSENT", "kind": "failure"})
        return 2
    if len(binding) > 10 or int(binding) < 3:
        _write({"code": "OUTPUT_BINDING_INVALID", "kind": "failure"})
        return 2
    try:
        with os.fdopen(os.dup(int(binding)), "wb", closefd=True) as stream:
            _revision_stream = stream
            return _generate_from_request()
    except BaseException:
        traceback.print_exc(file=sys.stderr)
        _write({"code": "GENERATION_FAILED", "kind": "failure"})
        return 2
    finally:
        _revision_stream = None


if __name__ == "__main__":
    raise SystemExit(main())
