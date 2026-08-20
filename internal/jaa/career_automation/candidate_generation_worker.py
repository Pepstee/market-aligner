"""Exact-clean isolated worker for sink-first candidate package generation."""

from __future__ import annotations

import base64
import hashlib
import json
import pickle
import sys
from pathlib import Path

from .application_compiler import CandidateContact
from cv_generation.service import build_candidate_application_package
from .evidence_matching import canonical_json


def _write(document: dict[str, object]) -> None:
    sys.stdout.write(canonical_json(document) + "\n")
    sys.stdout.flush()


def _revision_writer(**arguments: object) -> None:
    value = arguments.get("value")
    if not isinstance(value, bytes):
        raise TypeError("isolated generation revision must contain exact bytes")
    _write(
        {
            "kind": "revision",
            "role": arguments["role"],
            "media_type": arguments["media_type"],
            "prior_sha256": arguments.get("prior_sha256"),
            "approved": arguments.get("approved", True),
            "rejection_codes": list(arguments.get("rejection_codes", ())),
            "value_base64": base64.b64encode(value).decode("ascii"),
        }
    )


def main() -> int:
    request = json.loads(sys.stdin.buffer.read())
    if not isinstance(request, dict):
        raise ValueError("isolated generation request is malformed")
    contact_document = request.pop("contact")
    approved_evidence_path = request.pop("approved_evidence_path", None)
    if not isinstance(contact_document, dict):
        raise ValueError("isolated generation contact is malformed")
    contact = CandidateContact(**contact_document)
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


if __name__ == "__main__":
    raise SystemExit(main())
