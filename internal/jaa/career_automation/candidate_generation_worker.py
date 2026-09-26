"""Exact-clean isolated worker for sink-first candidate package generation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import sys
from pathlib import Path
from typing import BinaryIO

from .application_compiler import CandidateContact
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
        _write({"code": "GENERATION_FAILED", "kind": "failure"})
        return 2
    finally:
        _revision_stream = None


if __name__ == "__main__":
    raise SystemExit(main())
