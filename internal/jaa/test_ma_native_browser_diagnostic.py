"""Opt-in, local-only diagnostic for the native preparation path."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import stat
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import pytest


ACCEPTED_EVIDENCE = Path(
    "/srv/artvault/control/operator-glm/jobs/"
    "ma-second-example-20261001-20261001T210349Z/work/accepted-two-example-evidence.json"
)
ACCEPTED_EVIDENCE_SHA256 = (
    "8449a3f8a2940dea3770769483e1f0012151339e5f15ca85bc2d0de91ac4b730"
)
_MAX_NATIVE_RESPONSE_CAPTURE_BYTES = 1_048_576
_MAX_NATIVE_EXCEPTION_CHAIN_DEPTH = 6
_MAX_NATIVE_EXCEPTION_MESSAGE_BYTES = 4096
_MAX_NATIVE_EXCEPTION_CHAIN_BYTES = 32_768
NAMED_TEST_ROOT = Path(
    "/srv/artvault/control/operator-glm/programme/canary/"
    "market-aligner-linux-verification"
)
APPLICATION_URL = "http://127.0.0.1:1/synthetic/application"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    from career_automation.evidence_matching import canonical_json

    return (canonical_json(value) + "\n").encode("utf-8")


def _private_write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    path.chmod(0o600)


def _save_result(root: Path, result: dict[str, object]) -> None:
    _private_write(root / "safe-result.json", _json_bytes(result))


def _response_structure(text: str) -> dict[str, object]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        return {
            "json_status": "invalid",
            "json_root_type": None,
            "json_root_member_count": None,
            "json_error_line": error.lineno,
            "json_error_column": error.colno,
        }
    if isinstance(value, dict):
        root_type = "object"
        member_count = len(value)
    elif isinstance(value, list):
        root_type = "array"
        member_count = len(value)
    elif value is None:
        root_type = "null"
        member_count = None
    elif isinstance(value, bool):
        root_type = "boolean"
        member_count = None
    elif isinstance(value, (int, float)):
        root_type = "number"
        member_count = None
    else:
        root_type = "string"
        member_count = None
    return {
        "json_status": "valid",
        "json_root_type": root_type,
        "json_root_member_count": member_count,
        "json_error_line": None,
        "json_error_column": None,
    }


def _capture_provider_response(
    response: object, destination: Path | None
) -> dict[str, object]:
    if destination is None:
        return {"status": "not_requested"}
    text = getattr(response, "text", None)
    if not isinstance(text, str):
        return {
            "status": "response_text_unavailable",
            "response_type": type(response).__name__,
        }
    payload = text.encode("utf-8")
    summary: dict[str, object] = {
        "response_bytes": len(payload),
        "response_sha256": _sha(payload),
    }
    if len(payload) > _MAX_NATIVE_RESPONSE_CAPTURE_BYTES:
        summary["status"] = "too_large"
        return summary
    try:
        summary.update(_response_structure(text))
    except Exception as error:
        summary["json_status"] = "summary_failed"
        summary["json_error_type"] = type(error).__name__
    try:
        _private_write(destination, payload)
    except Exception as error:
        summary["status"] = "write_failed"
        summary["capture_error_type"] = type(error).__name__
        return summary
    summary["status"] = "written"
    return summary


def _capture_exception_chain(root: Path, error: BaseException) -> dict[str, object]:
    records: list[dict[str, object]] = []
    seen: set[int] = set()
    current: BaseException | None = error
    chain_truncated = False
    while current is not None and len(records) < _MAX_NATIVE_EXCEPTION_CHAIN_DEPTH:
        if id(current) in seen:
            chain_truncated = True
            break
        seen.add(id(current))
        try:
            message = str(current)
        except Exception:
            message = ""
        prefix = message[:_MAX_NATIVE_EXCEPTION_MESSAGE_BYTES]
        prefix_bytes = prefix.encode("utf-8", errors="replace")[
            :_MAX_NATIVE_EXCEPTION_MESSAGE_BYTES
        ]
        records.append(
            {
                "type": type(current).__name__,
                "message_prefix": prefix_bytes.decode("utf-8", errors="replace"),
                "captured_message_bytes": len(prefix_bytes),
                "captured_message_sha256": _sha(prefix_bytes),
                "message_truncated": len(prefix) < len(message)
                or len(prefix_bytes) < len(prefix.encode("utf-8", errors="replace")),
            }
        )
        next_error = current.__cause__
        if next_error is None and not current.__suppress_context__:
            next_error = current.__context__
        current = next_error
    if current is not None:
        chain_truncated = True
    document = {
        "schema_version": "ma.native-diagnostic-exception-chain.v1",
        "chain_truncated": chain_truncated,
        "causes": records,
    }
    backend_failure = getattr(error, "backend_failure", None)
    if isinstance(backend_failure, dict):
        document["backend_failure"] = backend_failure
    payload = _json_bytes(document)
    summary: dict[str, object] = {
        "status": "too_large" if len(payload) > _MAX_NATIVE_EXCEPTION_CHAIN_BYTES else "pending",
        "exception_chain_bytes": len(payload),
        "exception_chain_sha256": _sha(payload),
        "exception_chain_types": [row["type"] for row in records],
        "exception_chain_truncated": chain_truncated
        or any(row["message_truncated"] for row in records),
    }
    if len(payload) > _MAX_NATIVE_EXCEPTION_CHAIN_BYTES:
        return summary
    try:
        _private_write(root / "exception-chain.json", payload)
    except Exception as capture_error:
        summary["status"] = "write_failed"
        summary["capture_error_type"] = type(capture_error).__name__
        return summary
    summary["status"] = "written"
    return summary


def _capture_setup_failures(test_function):
    @wraps(test_function)
    def wrapped(*args, **kwargs):
        root = kwargs.get("tmp_path", args[0] if args else None)
        try:
            return test_function(*args, **kwargs)
        except Exception as error:
            if isinstance(root, Path) and root.is_dir():
                raw = str(error).encode("utf-8", errors="replace")
                if not (root / "actual-exception.txt").exists():
                    _private_write(root / "actual-exception.txt", raw)
                if not (root / "safe-result.json").exists():
                    _save_result(
                        root,
                        {
                            "diagnostic_only": True,
                            "synthetic_fixture": True,
                            "status": "setup_or_execution_exception",
                            "exception_type": type(error).__name__,
                            "exception_sha256": _sha(raw),
                            "external_network_requests": 0,
                            "external_submission": 0,
                        },
                    )
            raise

    return wrapped


def _make_fixture_contact(root: Path, monkeypatch) -> Path:
    import career_automation.candidate_contact_authority as contact_module
    from career_automation.candidate_contact_authority import (
        ATTESTATION,
        REGISTRY_ATTESTATION,
        REGISTRY_SCHEMA_VERSION,
        SCHEMA_VERSION,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_sha256 = _sha(public_raw)
    monkeypatch.setattr(
        contact_module, "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256", public_sha256
    )
    key_directory = root / "keys"
    key_directory.mkdir(mode=0o700)
    public_key_path = key_directory / "fixture-public.pem"
    _private_write(
        public_key_path,
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    registry_directory = root / "contact-registry"
    registry_directory.mkdir(mode=0o700)
    monkeypatch.setenv(contact_module.PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setenv(contact_module.REGISTRY_ENV, str(registry_directory))

    issued_at = datetime.now(timezone.utc).isoformat()
    signed_payload = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_explicit_operator_attestation",
        "operator_attestation": ATTESTATION,
        "issued_at": issued_at,
        "record_id": "synthetic-contact-record",
        "record_version": 1,
        "contact": {
            "full_name": "Alex Fixture",
            "email": "alex.fixture@fixture.invalid",
            "phone": None,
            "city": "Synthetic City",
        },
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": public_sha256,
    }
    signature = base64.b64encode(
        private_key.sign(_json_bytes(signed_payload))
    ).decode("ascii")
    content_addressed = {**signed_payload, "signature_base64": signature}
    authority_sha256 = _sha(_json_bytes(content_addressed))
    authority_path = root / f"{authority_sha256}.json"
    _private_write(
        authority_path,
        _json_bytes({**content_addressed, "authority_sha256": authority_sha256}),
    )

    registry_payload = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_operator_contact_registry",
        "operator_attestation": REGISTRY_ATTESTATION,
        "issued_at": issued_at,
        "registry_id": "operator-contact-primary",
        "registry_version": 1,
        "current": {
            "record_id": signed_payload["record_id"],
            "record_version": signed_payload["record_version"],
            "authority_sha256": authority_sha256,
        },
        "revoked_authority_sha256s": [],
        "prior_registry_sha256": None,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": public_sha256,
    }
    registry_signature = base64.b64encode(
        private_key.sign(_json_bytes(registry_payload))
    ).decode("ascii")
    registry_content = {
        **registry_payload,
        "signature_base64": registry_signature,
    }
    registry_sha256 = _sha(_json_bytes(registry_content))
    _private_write(
        registry_directory / f"{registry_sha256}.json",
        _json_bytes({**registry_content, "registry_sha256": registry_sha256}),
    )
    monkeypatch.setenv("JAA_CANDIDATE_CONTACT_AUTHORITY", str(authority_path))
    return authority_path


def _synthetic_projection(evidence_document: dict[str, object], evidence_bytes: bytes):
    rows = evidence_document.get("statements")
    if not isinstance(rows, list) or len(rows) < 8:
        raise ValueError("synthetic evidence fixture lacks its accepted fact set")
    approved_evidence = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("synthetic evidence fixture row is malformed")
        statement = row.get("statement")
        evidence_id = row.get("id")
        kind = row.get("kind")
        proof_class = row.get("proof_class")
        if (
            not isinstance(statement, str)
            or not isinstance(evidence_id, str)
            or not isinstance(kind, str)
            or proof_class != kind
        ):
            raise ValueError("synthetic evidence fixture lacks typed source bindings")
        approved_evidence.append(
            {
                "id": evidence_id,
                "statement_sha256": _sha(statement.encode("utf-8")),
                "kind": kind,
                "proof_class": proof_class,
            }
        )
    projection_body = {
        "policy_sha256": _sha(b"explicit synthetic local diagnostic policy"),
        "approved_evidence": approved_evidence,
        "source_hashes": {"approved_evidence": _sha(evidence_bytes)},
    }
    projection_sha256 = _sha(_json_bytes(projection_body))
    return {**projection_body, "projection_sha256": projection_sha256}


def _synthetic_decision(
    *,
    vacancy_sha256: str,
    projection: dict[str, object],
    evidence_document: dict[str, object],
    vacancy: dict[str, str],
    job_key: str,
):
    from career_automation.candidate_authority import fit_from_evidence_matrix

    evidence_ids = evidence_document.get("matched_evidence_ids")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or any(not isinstance(evidence_id, str) for evidence_id in evidence_ids)
        or len(set(evidence_ids)) != len(evidence_ids)
    ):
        raise ValueError("synthetic evidence fixture matched IDs are malformed")
    requirement = vacancy["requirement"]
    matrix = [
        {
            "requirement_id": "SYNTHETIC-REQ-1",
            "requirement_text": requirement,
            "requirement_text_sha256": _sha(requirement.encode("utf-8")),
            "classification": "essential",
            "status": "matched",
            "evidence_ids": evidence_ids,
            "suppressor_ids": [],
            "weight": "2",
        }
    ]
    return {
        "schema_version": "jaa.candidate-vacancy-decision-receipt.v1",
        "job_key": job_key,
        "role_title": vacancy["role_title"],
        "company_name": vacancy["company_name"],
        "source_url": APPLICATION_URL,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "vacancy_sha256": vacancy_sha256,
        "discovery_body_sha256": vacancy_sha256,
        "vacancy_description_sha256": _sha(vacancy["description"].encode("utf-8")),
        "candidate_projection_sha256": projection["projection_sha256"],
        "decision": "eligible",
        "fit": fit_from_evidence_matrix(matrix),
        "eligibility_checks": [],
        "reasons": [],
        "missing_facts": [],
        "evidence_matrix": matrix,
    }


def _synthetic_html(vacancy: dict[str, str]) -> str:
    return (
        "<!doctype html><html><head><title>"
        f"{html.escape(vacancy['role_title'])} at {html.escape(vacancy['company_name'])}"
        "</title></head><body><h1>"
        f"{html.escape(vacancy['role_title'])} at {html.escape(vacancy['company_name'])}"
        "</h1>"
        f"<p>{html.escape(vacancy['description'])}</p><form>"
        '<label for="full_name">Full name</label>'
        '<input id="full_name" name="full_name" required>'
        '<label for="email">Email</label>'
        '<input id="email" name="email" type="email" required>'
        '<label for="city">City</label>'
        '<input id="city" name="city" required>'
        '<label for="resume">CV</label>'
        '<input id="resume" name="resume" type="file" required>'
        '<label for="cover_letter">Cover letter</label>'
        '<input id="cover_letter" name="cover_letter" type="file">'
        '<button type="submit">Submit Application</button>'
        "</form></body></html>"
    )


class _OneCallBackend:
    name = "codex_cli"

    def __init__(self, backend, *, response_capture_path: Path | None = None) -> None:
        self.backend = backend
        self.response_capture_path = response_capture_path
        self.response_capture: dict[str, object] = {"status": "not_received"}
        self.call_attempts = 0
        self.dispatched = 0
        self.responses = 0
        self.backend_errors = 0
        self.refused_before_dispatch = 0
        self.response_model: str | None = None

    def available(self) -> bool:
        return self.backend.available()

    def _dispatch(self, invoke):
        self.call_attempts += 1
        if self.dispatched >= 1:
            self.refused_before_dispatch += 1
            from llm.client import LLMError

            raise LLMError(
                "synthetic diagnostic one-call limit: second backend dispatch refused"
            )
        self.dispatched += 1
        try:
            response = invoke()
        except Exception:
            self.backend_errors += 1
            raise
        self.responses += 1
        model = getattr(response, "model", None)
        self.response_model = model if isinstance(model, str) else None
        try:
            self.response_capture = _capture_provider_response(
                response, self.response_capture_path
            )
        except Exception as capture_error:
            self.response_capture = {
                "status": "capture_failed",
                "capture_error_type": type(capture_error).__name__,
            }
        return response

    def complete(self, system: str, user: str, temperature: float):
        return self._dispatch(
            lambda: self.backend.complete(system, user, temperature)
        )

    def complete_structured(
        self,
        system: str,
        user: str,
        temperature: float,
        *,
        schema: dict[str, object],
        task: str = "generic",
        image_bytes: tuple[bytes, ...] = (),
    ):
        from llm.client import LLMError

        structured = getattr(self.backend, "complete_structured", None)
        if not callable(structured):
            raise LLMError("wrapped backend does not support structured output")
        return self._dispatch(
            lambda: structured(
                system,
                user,
                temperature,
                schema=schema,
                task=task,
                **({"image_bytes": image_bytes} if image_bytes else {}),
            )
        )


def test_one_call_backend_forwards_review_images_without_second_dispatch() -> None:
    from llm.client import LLMError, LLMResponse

    class StructuredBackend:
        name = "codex_cli"

        def __init__(self) -> None:
            self.calls = 0
            self.image_bytes: tuple[bytes, ...] = ()

        def available(self) -> bool:
            return True

        def complete_structured(
            self,
            system: str,
            user: str,
            temperature: float,
            *,
            schema: dict[str, object],
            task: str = "generic",
            image_bytes: tuple[bytes, ...] = (),
        ) -> LLMResponse:
            self.calls += 1
            self.image_bytes = image_bytes
            return LLMResponse(text='{"verdict":"pass"}', model="synthetic")

    source = StructuredBackend()
    guarded = _OneCallBackend(source)
    images = (b"\x89PNG\r\n\x1a\nsynthetic-page",)
    response = guarded.complete_structured(
        "synthetic system",
        "synthetic user",
        0.0,
        schema={"type": "object"},
        image_bytes=images,
    )

    assert response.text == '{"verdict":"pass"}'
    assert source.calls == 1
    assert source.image_bytes == images
    with pytest.raises(LLMError, match="second backend dispatch refused"):
        guarded.complete_structured(
            "synthetic system",
            "synthetic user",
            0.0,
            schema={"type": "object"},
            image_bytes=images,
        )
    assert source.calls == 1
    assert guarded.dispatched == 1
    assert guarded.refused_before_dispatch == 1


@_capture_setup_failures
def test_native_prepare_release_one_call_local_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.environ.get("MA_RUN_NATIVE_BROWSER_DIAGNOSTIC") != "1":
        pytest.skip("opt-in native provider/browser diagnostic")
    repository_root = Path(__file__).resolve().parent
    expected_test_root = NAMED_TEST_ROOT / "internal" / "jaa"
    if repository_root != expected_test_root:
        pytest.fail("native diagnostic is admitted only in the exact named test tree")

    os.umask(0o077)
    tmp_path.chmod(0o700)
    if tmp_path.is_symlink() or not tmp_path.is_absolute():
        pytest.fail("diagnostic root must be a fresh private absolute directory")
    result: dict[str, object] = {
        "diagnostic_only": True,
        "synthetic_fixture": True,
        "production_admission": False,
        "external_network_enabled": False,
        "external_submission": False,
        "provider_model_selected": "gpt-6-luna",
        "provider_model_independently_attested": False,
        "source_url_sha256": _sha(APPLICATION_URL.encode("utf-8")),
    }
    evidence_bytes = ACCEPTED_EVIDENCE.read_bytes()
    evidence_sha256 = _sha(evidence_bytes)
    if evidence_sha256 != ACCEPTED_EVIDENCE_SHA256:
        pytest.fail("accepted synthetic evidence fixture digest differs")
    evidence_document = json.loads(evidence_bytes)
    vacancy_data = evidence_document.get("synthetic_vacancy")
    if (
        not isinstance(vacancy_data, dict)
        or any(
            not isinstance(vacancy_data.get(key), str)
            or not vacancy_data[key].strip()
            for key in ("company_name", "description", "requirement", "role_title")
        )
    ):
        pytest.fail("accepted synthetic vacancy fixture is malformed")
    vacancy_data = {
        key: vacancy_data[key]
        for key in ("company_name", "description", "requirement", "role_title")
    }
    job_key = "greenhouse:synthetic-local:" + evidence_sha256[:16]
    projection = _synthetic_projection(evidence_document, evidence_bytes)
    result["approved_evidence_sha256"] = evidence_sha256
    result["candidate_projection_sha256"] = projection["projection_sha256"]

    from career_automation import candidate_contact_authority as contact_module
    from career_automation import candidate_release_gate as gate_module
    from career_automation import gutua_greenhouse_session as session_module
    from career_automation import application_sanity_review as sanity_module
    from career_automation.application_archive import VacancyArchiveIdentity
    from career_automation.application_sanity_review import ApplicationSanityReviewError
    from career_automation.candidate_contact_authority import load_candidate_contact_authority
    from career_automation.production_attempt import GreenhouseAttemptRecorder
    from career_automation.production_queue import LiveVacancy, QueueItem
    from career_automation.production_runner import GeneratedRevisionSink
    from career_automation.gutua_greenhouse_session import GutuaGreenhouseSession
    from llm.client import CodexCliBackend, LLMClient

    contact_path = _make_fixture_contact(tmp_path, monkeypatch)
    contact_authority = load_candidate_contact_authority(
        contact_path, repository_root=repository_root
    )
    result["contact_authority_sha256"] = contact_authority.authority_sha256

    html_text = _synthetic_html(vacancy_data)
    vacancy_body = html_text.encode("utf-8")
    vacancy_sha256 = _sha(vacancy_body)
    decision = _synthetic_decision(
        vacancy_sha256=vacancy_sha256,
        projection=projection,
        evidence_document=evidence_document,
        vacancy=vacancy_data,
        job_key=job_key,
    )
    decision_bytes = _json_bytes(decision)
    decision_sha256 = _sha(decision_bytes)
    result.update(
        vacancy_sha256=vacancy_sha256,
        decision_receipt_sha256=decision_sha256,
    )
    vacancy = VacancyArchiveIdentity(
        job_key,
        vacancy_sha256,
        vacancy_data["role_title"],
        vacancy_data["company_name"],
        APPLICATION_URL,
    )
    live = LiveVacancy.create(
        vacancy=vacancy,
        provider="greenhouse",
        fit_score=decision["fit"],
        live=True,
        eligible=True,
        duplicate=False,
        live_verified_at=decision["observed_at"],
        scoring_inputs_sha256=decision_sha256,
    )
    item = QueueItem(live, 1, "new_attempt")
    archive_root = tmp_path / "archive"
    archive_root.mkdir(mode=0o700)
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=archive_root,
        repository_root=repository_root,
        vacancy=vacancy,
        complete_vacancy=vacancy_body,
        structured_vacancy={
            "job_key": job_key,
            "source_url": APPLICATION_URL,
            "role_title": vacancy_data["role_title"],
            "company_name": vacancy_data["company_name"],
            "synthetic": True,
        },
        assessment={"synthetic": True},
    )
    result["attempt_id"] = recorder.attempt.attempt_id

    discovery_path = tmp_path / "synthetic-discovery.json"
    _private_write(discovery_path, _json_bytes({"synthetic": True}))
    authority_directory = archive_root / "candidate-authorities"
    authority_directory.mkdir(mode=0o700)
    eligibility_document = {
        "schema_version": "jaa.production-candidate-authority.v2",
        "candidate_projection": projection,
        "synthetic": True,
    }
    eligibility_bytes = _json_bytes(eligibility_document)
    eligibility_sha256 = _sha(eligibility_bytes)
    eligibility_path = authority_directory / f"{eligibility_sha256}.json"
    _private_write(eligibility_path, eligibility_bytes)

    session = object.__new__(GutuaGreenhouseSession)
    session.approved_evidence_path = ACCEPTED_EVIDENCE
    session.local_synthetic_review_fixture_sha256 = ACCEPTED_EVIDENCE_SHA256
    session.archive_root = archive_root
    session.repository_root = repository_root
    session.candidate_projection = projection
    session.decision_by_key = {
        job_key: {
            "job_key": job_key,
            "receipt": decision,
            "receipt_sha256": decision_sha256,
        }
    }
    session.complete_vacancy_by_key = {job_key: vacancy_body}
    session.discovery_path = discovery_path
    session.eligibility_path = eligibility_path

    duplicate_sha256 = _sha(b"synthetic local duplicate snapshot")
    monkeypatch.setattr(
        gate_module,
        "_verify_durable_candidate_authority",
        lambda *_args, **_kwargs: {
            "job_key": job_key,
            "role_title": vacancy_data["role_title"],
            "company_name": vacancy_data["company_name"],
            "vacancy_sha256": vacancy_sha256,
            "source_url": APPLICATION_URL,
            "candidate_authority_sha256": eligibility_sha256,
            "candidate_decision_receipt_sha256": decision_sha256,
            "candidate_projection_sha256": projection["projection_sha256"],
            "duplicate_snapshot_sha256": duplicate_sha256,
            "contact_authority_sha256": contact_authority.authority_sha256,
            "contact_registry_sha256": contact_authority.registry_sha256,
        },
    )
    observation = _json_bytes(
        {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "synthetic": True,
            "provider_loader_paths": {
                "confirmation_message": "Synthetic fixture confirmation",
                "confirmationPath": "/example/jobs/1234567/confirmation",
            },
        }
    )

    class _ObservationReceipt:
        observation_sha256 = _sha(observation)

    monkeypatch.setattr(
        session_module,
        "load_provider_observation_authority",
        lambda **_kwargs: (observation, _ObservationReceipt()),
    )

    backend = _OneCallBackend(
        CodexCliBackend(model="gpt-6-luna", cli_timeout_seconds=300.0),
        response_capture_path=tmp_path / "provider-response.txt",
    )
    class _LLMClientFactory:
        @staticmethod
        def from_config(**kwargs):
            return LLMClient(
                backend=backend,
                model="codex-cli-default",
                temperature=kwargs.get("temperature", 0),
                max_retries=1,
                cache_enabled=False,
                cache_dir=kwargs["cache_dir"],
                transport_archive_dir=kwargs["transport_archive_dir"],
                usage_log=kwargs["usage_log"],
            )

    monkeypatch.setattr(session_module, "LLMClient", _LLMClientFactory)
    review_receipts: list[object] = []
    real_review = session_module.review_application_package_with_pinned_skills

    def capture_review(package, *, client, **review_kwargs):
        receipt = real_review(package, client=client, **review_kwargs)
        document = receipt.document()
        default_verification_rejected = False
        try:
            sanity_module.verify_sanity_review_receipt(receipt, package)
        except ValueError as verification_error:
            default_verification_rejected = (
                receipt.schema_version
                == sanity_module.LOCAL_SYNTHETIC_DIAGNOSTIC_RECEIPT_SCHEMA_VERSION
                and str(verification_error)
                == "local diagnostic receipt is rejected by production verification"
            )
        result[
            "default_production_verifier_rejected_actual_diagnostic_receipt"
        ] = default_verification_rejected
        result["captured_sanity_receipt_schema_version"] = receipt.schema_version
        receipt_bytes = _json_bytes(document)
        recorder.add_revision(
            role="review.sanity_result",
            value=receipt_bytes,
            media_type="application/json",
            prior_sha256=None,
            approved=True,
        )
        _private_write(tmp_path / "sanity-review-receipt.json", receipt_bytes)
        review_receipts.append(receipt)
        result["sanity_receipt_sha256"] = _sha(receipt_bytes)
        result["sanity_receipt_model_identity"] = str(
            document.get("model_identity", "")
        )
        result["sanity_receipt_package_hashes_sha256"] = _sha(
            _json_bytes(document.get("package_hashes", {}))
        )
        coverage = document.get("review_coverage")
        if isinstance(coverage, dict):
            result["combined_review_schema_version"] = document.get("schema_version")
            result["combined_review_projection_sha256"] = coverage.get(
                "applicant_visible_projection_sha256"
            )
            result["combined_review_stage"] = coverage.get("review_stage")
            result["diagnostic_context_sha256"] = coverage.get(
                "diagnostic_context_sha256"
            )
            result["production_admission"] = coverage.get("production_admission")
            result["execution_scope"] = coverage.get("execution_scope")
            result["combined_review_criteria"] = [
                row.get("criterion_id")
                for row in coverage.get("criteria", [])
                if isinstance(row, dict)
            ]
        model_result = document.get("model_result")
        sanity_result = (
            model_result.get("sanity_review")
            if isinstance(model_result, dict)
            else None
        )
        findings = (
            sanity_result.get("findings") if isinstance(sanity_result, dict) else None
        )
        if isinstance(findings, list):
            result["sanity_finding_codes"] = sorted(
                str(row.get("code"))
                for row in findings
                if isinstance(row, dict) and isinstance(row.get("code"), str)
            )
        criteria_reviews = (
            model_result.get("criteria_reviews")
            if isinstance(model_result, dict)
            else None
        )
        if isinstance(criteria_reviews, list):
            result["criteria_finding_codes"] = {
                str(row.get("criterion_id")): sorted(
                    str(finding.get("code"))
                    for finding in row.get("findings", [])
                    if isinstance(finding, dict)
                    and isinstance(finding.get("code"), str)
                )
                for row in criteria_reviews
                if isinstance(row, dict)
            }
        return receipt

    monkeypatch.setattr(
        session_module,
        "review_application_package_with_pinned_skills",
        capture_review,
    )
    fill_results: list[tuple[object, ...]] = []
    real_fill = GutuaGreenhouseSession._fill_supported_form

    def capture_fill(active_session, *args, **kwargs):
        fill_result = real_fill(active_session, *args, **kwargs)
        fill_results.append(fill_result)
        result["native_fill_returned"] = True
        result["uploaded_document_roles"] = sorted(str(row) for row in fill_result[0])
        result["native_fill_observation_count"] = len(fill_results)
        return fill_result

    monkeypatch.setattr(GutuaGreenhouseSession, "_fill_supported_form", capture_fill)

    served = {"fixture_get": 0, "aborted_requests": 0, "post_attempts": 0}
    prepared = None
    error: Exception | None = None
    browser = None
    page = None
    finalized = False
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
                session._playwright = playwright
                session._browser = browser
                page = browser.new_page(service_workers="block")

                def route_request(route) -> None:
                    request = route.request
                    if (
                        request.url == APPLICATION_URL
                        and request.method == "GET"
                        and served["fixture_get"] == 0
                    ):
                        served["fixture_get"] += 1
                        route.fulfill(
                            status=200,
                            content_type="text/html; charset=utf-8",
                            body=html_text,
                        )
                        return
                    if request.method == "POST":
                        served["post_attempts"] += 1
                    served["aborted_requests"] += 1
                    route.abort()

                page.route("**/*", route_request)
                page.goto(APPLICATION_URL)
                recorder.record_navigation(
                    {
                        "method": "GET",
                        "status": 200,
                        "url": APPLICATION_URL,
                        "synthetic_route_fulfilled": True,
                        "network_exit": False,
                    }
                )
                recorder.record_prefill(page)
                sink = GeneratedRevisionSink(recorder)
                prepared = session.prepare_release(item, recorder, page, sink)
            except Exception as exc:
                error = exc
            finally:
                try:
                    if error is not None:
                        error_bytes = str(error).encode("utf-8", errors="replace")
                        if not (tmp_path / "actual-exception.txt").exists():
                            _private_write(tmp_path / "actual-exception.txt", error_bytes)
                        result["exception_sha256"] = _sha(error_bytes)
                        result["exception_type"] = type(error).__name__
                    if len(review_receipts) > 1:
                        result["invariant_violation"] = "multiple_sanity_receipts"
                    if error is not None and isinstance(error, ApplicationSanityReviewError):
                        raw_review = error.result
                        if raw_review is not None:
                            review_document = dict(raw_review)
                            review_bytes = _json_bytes(review_document)
                            _private_write(
                                tmp_path / "sanity-review-result.json", review_bytes
                            )
                            result["sanity_result_sha256"] = _sha(review_bytes)
                            sanity_result = review_document.get("sanity_review")
                            findings = (
                                sanity_result.get("findings")
                                if isinstance(sanity_result, dict)
                                else review_document.get("findings")
                            )
                            if isinstance(findings, list):
                                result["sanity_finding_codes"] = sorted(
                                    str(row.get("code"))
                                    for row in findings
                                    if isinstance(row, dict)
                                    and isinstance(row.get("code"), str)
                                )
                            criteria_reviews = review_document.get("criteria_reviews")
                            if isinstance(criteria_reviews, list):
                                result["criteria_finding_codes"] = {
                                    str(row.get("criterion_id")): sorted(
                                        str(finding.get("code"))
                                        for finding in row.get("findings", [])
                                        if isinstance(finding, dict)
                                        and isinstance(finding.get("code"), str)
                                    )
                                    for row in criteria_reviews
                                    if isinstance(row, dict)
                                }
                    reason = (
                        "synthetic_diagnostic_stopped_before_submit"
                        if prepared is not None
                        else "diagnostic_preintent_failure"
                    )
                    message = (
                        "Diagnostic ended before any submit action"
                        if error is None
                        else "Native diagnostic stopped before any submit action"
                    )
                    recorder.finalize_preintent_failure(
                        page,
                        reason_code=reason,
                        error_type=type(error).__name__ if error else "DiagnosticStop",
                        error_message=message,
                    )
                    finalized = True
                except Exception as archive_error:
                    archive_bytes = str(archive_error).encode("utf-8", errors="replace")
                    if not (tmp_path / "archive-exception.txt").exists():
                        _private_write(tmp_path / "archive-exception.txt", archive_bytes)
                    result["archive_error_type"] = type(archive_error).__name__
                    result["archive_exception_sha256"] = _sha(archive_bytes)
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:
                        result["browser_close_error"] = True
    except Exception as exc:
        error = exc

    if error is not None and not (tmp_path / "actual-exception.txt").exists():
        error_bytes = str(error).encode("utf-8", errors="replace")
        _private_write(tmp_path / "actual-exception.txt", error_bytes)
        result["exception_sha256"] = _sha(error_bytes)
        result["exception_type"] = type(error).__name__
    if error is not None:
        try:
            exception_capture = _capture_exception_chain(tmp_path, error)
            result.update(
                exception_chain_capture_status=exception_capture["status"],
                exception_chain_bytes=exception_capture["exception_chain_bytes"],
                exception_chain_sha256=exception_capture["exception_chain_sha256"],
                exception_chain_types=exception_capture["exception_chain_types"],
                exception_chain_truncated=exception_capture[
                    "exception_chain_truncated"
                ],
            )
            if isinstance(error, ApplicationSanityReviewError):
                result["review_error_code"] = error.code
                backend_failure = error.backend_failure
                if isinstance(backend_failure, dict):
                    result["review_backend_failure_category"] = backend_failure.get(
                        "error_category"
                    )
                    result["review_backend_failure_exit_code"] = backend_failure.get(
                        "exit_code"
                    )
                    result["review_backend_diagnosis_present"] = bool(
                        backend_failure.get("stderr_diagnosis")
                    )
        except Exception as capture_error:
            result["exception_chain_capture_status"] = "capture_failed"
            result["exception_chain_capture_error_type"] = type(
                capture_error
            ).__name__

    objects = recorder.attempt._objects(recorder.attempt._events())
    roles = sorted(row.role for row in objects)
    result.update(
        provider_backend_calls=backend.call_attempts,
        provider_dispatches=backend.dispatched,
        provider_responses=backend.responses,
        provider_backend_errors=backend.backend_errors,
        provider_refused_before_dispatch=backend.refused_before_dispatch,
        provider_response_model=backend.response_model,
        provider_response_capture_status=backend.response_capture.get("status"),
        provider_response_bytes=backend.response_capture.get("response_bytes"),
        provider_response_sha256=backend.response_capture.get("response_sha256"),
        provider_response_json_status=backend.response_capture.get("json_status"),
        provider_response_json_root_type=backend.response_capture.get(
            "json_root_type"
        ),
        provider_response_json_root_member_count=backend.response_capture.get(
            "json_root_member_count"
        ),
        provider_response_json_error_line=backend.response_capture.get(
            "json_error_line"
        ),
        provider_response_json_error_column=backend.response_capture.get(
            "json_error_column"
        ),
        provider_response_capture_error_type=backend.response_capture.get(
            "capture_error_type"
        ),
        fixture_gets_fulfilled=served["fixture_get"],
        intercepted_requests_aborted=served["aborted_requests"],
        intercepted_post_attempts=served["post_attempts"],
        external_network_requests=0,
        external_submission=0,
        prepared_returned=prepared is not None,
        attempt_finalized=finalized,
        terminal_archive_roles=roles,
    )
    if error is None:
        result["status"] = "prepared_no_submit"
        result["prepared_result_type"] = type(prepared).__name__
        if isinstance(prepared, session_module.PreparedLocalSyntheticDiagnostic):
            result["production_admission"] = prepared.production_admission
            result["submission_authority"] = prepared.submission_authority
            result["native_fill_declared_completed"] = prepared.native_fill_completed
            result["diagnostic_context_sha256"] = (
                prepared.diagnostic_context.context_sha256
            )
    elif backend.refused_before_dispatch and result.get("native_fill_returned"):
        result["status"] = "stopped_after_fill_before_second_provider_dispatch"
    elif isinstance(error, ApplicationSanityReviewError) and error.result is not None:
        result["status"] = "sanity_review_blocked"
    elif isinstance(error, ApplicationSanityReviewError) and error.backend_failure is not None:
        result["status"] = "sanity_backend_failure"
    else:
        result["status"] = "native_diagnostic_failed"
    _save_result(tmp_path, result)
    print(json.dumps(result, sort_keys=True))

    assert result["provider_dispatches"] <= 1
    assert result["external_network_requests"] == 0
    assert result["intercepted_post_attempts"] == 0
    assert result["external_submission"] == 0
    assert result["attempt_id"]
    if page is not None:
        assert "submission.result" in result["terminal_archive_roles"]
        assert result["attempt_finalized"] is True
    if review_receipts:
        assert (
            result.get(
                "default_production_verifier_rejected_actual_diagnostic_receipt"
            )
            is True
        )
    if result["status"] == "native_diagnostic_failed":
        pytest.fail("native diagnostic failed; inspect private exception evidence")
    if result["status"] != "prepared_no_submit":
        pytest.fail(
            "native diagnostic stopped at a captured boundary; inspect safe result"
        )
    assert backend.dispatched == 1
    assert backend.responses == 1
    assert len(review_receipts) == 1
    assert isinstance(prepared, session_module.PreparedLocalSyntheticDiagnostic)
    assert prepared.production_admission is False
    assert prepared.submission_authority is False
    assert result.get("native_fill_returned") is True
    assert result.get("native_fill_observation_count") == 1
    assert "cv" in result.get("uploaded_document_roles", [])
    assert result.get("native_fill_declared_completed") is True
    assert result["attempt_finalized"] is True
    assert "submission.result" in result["terminal_archive_roles"]


def test_native_response_capture_preserves_exact_bytes_and_one_call_limit(
    tmp_path: Path,
) -> None:
    from llm.client import LLMError, LLMResponse

    tmp_path.chmod(0o700)
    text = '{"verdict":"uncertain","detail":"synthetic diagnostic"}\n'
    response = LLMResponse(text=text, model="synthetic-model")

    class _FakeBackend:
        calls = 0

        def complete(self, system: str, user: str, temperature: float):
            self.calls += 1
            return response

    fake = _FakeBackend()
    response_path = tmp_path / "provider-response.txt"
    backend = _OneCallBackend(fake, response_capture_path=response_path)
    returned = backend.complete("synthetic system", "synthetic user", 0)

    assert returned is response
    assert response_path.read_bytes() == text.encode("utf-8")
    assert stat.S_IMODE(response_path.stat().st_mode) == 0o600
    assert backend.response_capture == {
        "response_bytes": len(text.encode("utf-8")),
        "response_sha256": _sha(text.encode("utf-8")),
        "json_status": "valid",
        "json_root_type": "object",
        "json_root_member_count": 2,
        "json_error_line": None,
        "json_error_column": None,
        "status": "written",
    }
    assert "synthetic diagnostic" not in json.dumps(backend.response_capture)

    with pytest.raises(LLMError, match="second backend dispatch refused"):
        backend.complete("synthetic system", "synthetic user", 0)
    assert fake.calls == 1
    assert backend.dispatched == 1
    assert backend.responses == 1
    assert backend.refused_before_dispatch == 1
    assert response_path.read_bytes() == text.encode("utf-8")


@pytest.mark.parametrize("first_method", ("plain", "structured"))
def test_native_one_call_backend_shares_guard_across_transport_methods(
    first_method: str,
) -> None:
    from llm.client import LLMError, LLMResponse

    response = LLMResponse(text='{"result":"synthetic"}', model="synthetic-model")
    schema = {"type": "object", "required": ["result"]}

    class _FakeBackend:
        plain_calls = 0
        structured_calls = 0
        observed_schema = None
        observed_task = None

        def available(self) -> bool:
            return True

        def complete(self, system: str, user: str, temperature: float):
            self.plain_calls += 1
            return response

        def complete_structured(
            self,
            system: str,
            user: str,
            temperature: float,
            *,
            schema: dict[str, object],
            task: str,
        ):
            self.structured_calls += 1
            self.observed_schema = schema
            self.observed_task = task
            return response

    fake = _FakeBackend()
    backend = _OneCallBackend(fake)
    if first_method == "structured":
        first_response = backend.complete_structured(
            "synthetic system",
            "synthetic user",
            0.0,
            schema=schema,
            task="synthetic-review",
        )
        second_call = lambda: backend.complete("synthetic system", "synthetic user", 0.0)
    else:
        first_response = backend.complete("synthetic system", "synthetic user", 0.0)
        second_call = lambda: backend.complete_structured(
            "synthetic system",
            "synthetic user",
            0.0,
            schema=schema,
            task="synthetic-review",
        )

    assert first_response is response
    with pytest.raises(LLMError, match="second backend dispatch refused"):
        second_call()
    assert fake.plain_calls == (first_method == "plain")
    assert fake.structured_calls == (first_method == "structured")
    if first_method == "structured":
        assert fake.observed_schema is schema
        assert fake.observed_task == "synthetic-review"
    assert backend.call_attempts == 2
    assert backend.dispatched == 1
    assert backend.responses == 1
    assert backend.refused_before_dispatch == 1


def test_native_response_capture_refuses_oversize_without_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from llm.client import LLMResponse

    tmp_path.chmod(0o700)
    monkeypatch.setattr(
        __import__(__name__), "_MAX_NATIVE_RESPONSE_CAPTURE_BYTES", 8
    )
    response_path = tmp_path / "provider-response.txt"
    response = LLMResponse(text="synthetic-too-large", model="synthetic-model")

    summary = _capture_provider_response(response, response_path)

    assert summary["status"] == "too_large"
    assert summary["response_bytes"] == len(response.text.encode("utf-8"))
    assert summary["response_sha256"] == _sha(response.text.encode("utf-8"))
    assert not response_path.exists()


def test_native_exception_chain_capture_is_bounded_and_private(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    try:
        try:
            raise ValueError("synthetic cause " + "x" * 6000)
        except ValueError as cause:
            raise RuntimeError("synthetic wrapper") from cause
    except RuntimeError as error:
        summary = _capture_exception_chain(tmp_path, error)

    artifact = tmp_path / "exception-chain.json"
    assert summary["status"] == "written"
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert artifact.stat().st_size <= _MAX_NATIVE_EXCEPTION_CHAIN_BYTES
    document = json.loads(artifact.read_bytes())
    assert [row["type"] for row in document["causes"]] == [
        "RuntimeError",
        "ValueError",
    ]
    assert document["causes"][1]["message_truncated"] is True
    assert summary["exception_chain_truncated"] is True
