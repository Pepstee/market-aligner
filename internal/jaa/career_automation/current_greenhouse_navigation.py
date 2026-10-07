"""Typed proof for an authenticated current Greenhouse navigation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Mapping
from urllib.parse import urlsplit

from .evidence_matching import canonical_json
from .greenhouse_loader_contract import parse_current_greenhouse_loader
from .provider_observation_capture import (
    _redact_sensitive_response,
    exact_clean_head,
)

_CAPTURE_ISSUER = object()
_PROOF_ISSUER = object()
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_CODE_PATHS = (
    "internal/jaa/career_automation/current_greenhouse_navigation.py",
    "internal/jaa/career_automation/greenhouse_loader_contract.py",
    "internal/jaa/career_automation/gutua_greenhouse_session.py",
    "internal/jaa/career_automation/production_attempt.py",
    "internal/jaa/career_automation/browser_executor.py",
)


def _bytes(document: Mapping[str, object]) -> bytes:
    return (canonical_json(document) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _context_binding(context) -> dict[str, object]:
    from .candidate_application_factory import (
        CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA,
        CURRENT_RUNTIME_ENVIRONMENT,
        MarketApplicationDecisionAuthority,
    )
    from .market_aligner_preparation import MarketApplicationMaterializationContext

    if type(context) is not MarketApplicationMaterializationContext:
        raise TypeError("current navigation requires an admitted Market context")
    context.__post_init__()
    authority = context.market_decision_authority
    if (
        type(authority) is not MarketApplicationDecisionAuthority
        or authority.environment != CURRENT_RUNTIME_ENVIRONMENT
        or authority.schema_version != CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA
        or authority.release_authority is not False
        or context.release_authority is not False
    ):
        raise ValueError("current navigation lacks a non-release Market authority")
    return {
        "admission_receipt_sha256": authority.admission_receipt_sha256,
        "application_id": context.application_id,
        "candidate_authority_file_sha256": authority.candidate_authority_file_sha256,
        "candidate_intent_sha256": context.candidate_intent_sha256,
        "candidate_projection_sha256": authority.candidate_projection_sha256,
        "current_boundary_receipt_sha256": authority.current_boundary_receipt_sha256,
        "environment": authority.environment,
        "handoff_root_sha256": authority.handoff_root_sha256,
        "market_authority_sha256": authority.authority_sha256,
        "profile_binding_sha256": _sha256(
            canonical_json(
                {
                    "profile_id": context.profile_id,
                    "profile_version": context.profile_version,
                }
            ).encode("utf-8")
        ),
        "raw_listing_sha256": authority.raw_listing_sha256,
        "source_job_key": authority.source_job_key,
        "source_url": authority.source_url,
    }


def _code_identity(repository_root: str | Path) -> tuple[str, tuple[tuple[str, str], ...]]:
    root = Path(repository_root).resolve(strict=True)
    head = exact_clean_head(root)
    hashes: list[tuple[str, str]] = []
    for relative in _CODE_PATHS:
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True).parent != path.parent:
            raise ValueError("current navigation source identity is unavailable")
        hashes.append((relative, _sha256(path.read_bytes())))
    return head, tuple(hashes)


def _loader_document(value: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "source_url",
        "job_post_id",
        "primary_response_sha256",
        "confirmationPath",
        "submitPath",
        "confirmation_message",
        "confirmation_url",
        "required_visible_markers",
    }
    if type(value) is not dict or set(value) != expected:
        raise ValueError("current navigation parser returned an invalid document")
    if any(type(value[key]) is not str or not value[key] for key in expected - {"required_visible_markers"}):
        raise ValueError("current navigation parser returned malformed text")
    markers = value["required_visible_markers"]
    if (
        type(markers) is not tuple
        or not markers
        or any(type(marker) is not str or not marker or marker != marker.strip() for marker in markers)
    ):
        raise ValueError("current navigation parser returned malformed markers")
    if not _HEX_64.fullmatch(value["primary_response_sha256"]):
        raise ValueError("current navigation parser returned an invalid response hash")
    return dict(value)


def _redacted_loader_capture(
    primary_response: bytes, *, source_url: str
) -> tuple[str, bytes, bytes]:
    original = _loader_document(
        parse_current_greenhouse_loader(primary_response, source_url=source_url)
    )
    redacted_response = _redact_sensitive_response(primary_response)
    redacted = _loader_document(
        parse_current_greenhouse_loader(redacted_response, source_url=source_url)
    )
    original_config = {
        key: value
        for key, value in original.items()
        if key != "primary_response_sha256"
    }
    redacted_config = {
        key: value
        for key, value in redacted.items()
        if key != "primary_response_sha256"
    }
    original_sha256 = _sha256(primary_response)
    redacted_sha256 = _sha256(redacted_response)
    if (
        original_config != redacted_config
        or original["primary_response_sha256"] != original_sha256
        or redacted["primary_response_sha256"] != redacted_sha256
    ):
        raise ValueError("redacted current Greenhouse loader differs from its source")
    return original_sha256, redacted_response, _bytes(redacted)


class _CaptureBindingToken:
    def __init__(self) -> None:
        self._lock = Lock()
        self._reserved_attempt: str | None = None
        self._consumed = False

    def reserve(self, attempt_id: str) -> None:
        with self._lock:
            if self._consumed or self._reserved_attempt is not None:
                raise ValueError("current Greenhouse capture was already bound")
            self._reserved_attempt = attempt_id

    def consume(self, attempt_id: str) -> None:
        with self._lock:
            if self._consumed or (
                self._reserved_attempt is not None
                and self._reserved_attempt != attempt_id
            ):
                raise ValueError("current Greenhouse capture was already bound")
            self._reserved_attempt = attempt_id
            self._consumed = True


@dataclass(frozen=True)
class CurrentGreenhouseNavigationCapture:
    """Process-local capture created only from the original page navigation."""

    page_identity: int = field(repr=False)
    source_url: str
    response_url: str
    method: str
    status: int
    observed_at: str
    primary_response_sha256: str
    redacted_response: bytes = field(repr=False)
    redacted_response_sha256: str
    loader_config: bytes = field(repr=False)
    loader_config_sha256: str
    market_context_sha256: str
    market_binding: tuple[tuple[str, object], ...]
    repository_head: str
    code_source_sha256s: tuple[tuple[str, str], ...]
    _issuer: object = field(repr=False, compare=False)
    _binding_token: _CaptureBindingToken = field(
        default_factory=_CaptureBindingToken, repr=False, compare=False
    )

    @property
    def loader_document(self) -> dict[str, object]:
        value = json.loads(self.loader_config)
        if type(value) is not dict:
            raise ValueError("archived Greenhouse loader configuration is malformed")
        value["required_visible_markers"] = tuple(
            value.get("required_visible_markers", ())
        )
        return value


@dataclass(frozen=True)
class CurrentGreenhouseNavigationProof:
    """Attempt-bound typed proof; this is not submission or release authority."""

    attempt_id: str
    navigation_event_sha256: str
    application_id: str
    job_key: str
    vacancy_sha256: str
    source_url: str
    response_url: str
    method: str
    status: int
    observed_at: str
    primary_response_sha256: str
    redacted_response_sha256: str
    loader_config_sha256: str
    market_context_sha256: str
    market_binding: tuple[tuple[str, object], ...]
    repository_head: str
    code_source_sha256s: tuple[tuple[str, str], ...]
    loader_config: bytes = field(repr=False)
    redacted_response: bytes = field(repr=False)
    page_identity: int = field(repr=False)
    proof_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def loader_document(self) -> dict[str, object]:
        value = json.loads(self.loader_config)
        if type(value) is not dict:
            raise ValueError("current Greenhouse loader configuration is malformed")
        value["required_visible_markers"] = tuple(
            value.get("required_visible_markers", ())
        )
        return _loader_document(value)

    def observation_bytes(self) -> bytes:
        loader = self.loader_document()
        return _bytes(
            {
                "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
                "provider": "greenhouse",
                "observed_at": self.observed_at,
                "request": {
                    "method": self.method,
                    "status": self.status,
                    "url": self.response_url,
                },
                "provider_loader_paths": {
                    "confirmationPath": loader["confirmationPath"],
                    "confirmation_message": loader["confirmation_message"],
                    "submitPath": loader["submitPath"],
                },
                "interaction": {
                    "fields_filled": 0,
                    "files_uploaded": 0,
                    "submit_clicks": 0,
                },
            }
        )

    def document(self) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": "jaa.greenhouse-current-navigation-proof.v1",
            "authority_kind": "owned_current_navigation_observation",
            "attempt_id": self.attempt_id,
            "navigation_event_sha256": self.navigation_event_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "vacancy_sha256": self.vacancy_sha256,
            "source_url": self.source_url,
            "response_url": self.response_url,
            "method": self.method,
            "status": self.status,
            "observed_at": self.observed_at,
            "primary_response_sha256": self.primary_response_sha256,
            "redacted_response_sha256": self.redacted_response_sha256,
            "loader_config_sha256": self.loader_config_sha256,
            "success_observation_sha256": _sha256(self.observation_bytes()),
            "market_context_sha256": self.market_context_sha256,
            "market_binding": dict(self.market_binding),
            "repository_head": self.repository_head,
            "code_source_sha256s": [
                {"path": path, "sha256": digest}
                for path, digest in self.code_source_sha256s
            ],
            "release_authority": False,
            "submission_authority": False,
        }
        expected = _sha256(_bytes(value))
        if expected != self.proof_sha256:
            raise ValueError("current Greenhouse proof identity is inconsistent")
        value["proof_sha256"] = expected
        return value


def capture_current_greenhouse_navigation(
    response,
    *,
    page,
    context,
    repository_root: str | Path,
) -> CurrentGreenhouseNavigationCapture:
    binding = _context_binding(context)
    source_url = str(binding["source_url"])
    try:
        request = response.request
        method = str(request.method).upper()
        response_url = str(response.url)
        status = response.status
        body = response.body()
    except Exception as exc:
        raise ValueError("current Greenhouse navigation response is unavailable") from exc
    if (
        type(body) is not bytes
        or method != "GET"
        or type(status) is not int
        or not 200 <= status < 300
        or response_url != source_url
        or str(page.url) != source_url
    ):
        raise ValueError("current Greenhouse navigation differs from its exact source")
    primary_response_sha256, redacted, loader_config = _redacted_loader_capture(
        body, source_url=source_url
    )
    loader = json.loads(loader_config)
    loader["required_visible_markers"] = tuple(loader["required_visible_markers"])
    if (
        loader["source_url"] != source_url
        or loader["job_post_id"]
        != str(binding["source_job_key"]).rsplit(":", 1)[-1]
    ):
        raise ValueError("redacted current Greenhouse loader differs from Market source")
    head, code_hashes = _code_identity(repository_root)
    context_sha256 = _sha256(canonical_json(binding).encode("utf-8"))
    return CurrentGreenhouseNavigationCapture(
        page_identity=id(page),
        source_url=source_url,
        response_url=response_url,
        method=method,
        status=status,
        observed_at=_utc_now(),
        primary_response_sha256=primary_response_sha256,
        redacted_response=redacted,
        redacted_response_sha256=_sha256(redacted),
        loader_config=loader_config,
        loader_config_sha256=_sha256(loader_config),
        market_context_sha256=context_sha256,
        market_binding=tuple(sorted(binding.items())),
        repository_head=head,
        code_source_sha256s=code_hashes,
        _issuer=_CAPTURE_ISSUER,
    )


def bind_current_greenhouse_navigation(
    capture: CurrentGreenhouseNavigationCapture,
    *,
    attempt_id: str,
    navigation_event_sha256: str,
    vacancy,
) -> CurrentGreenhouseNavigationProof:
    token = _validate_capture_attempt_binding(
        capture, attempt_id=attempt_id, vacancy=vacancy
    )
    if (
        type(navigation_event_sha256) is not str
        or not _HEX_64.fullmatch(navigation_event_sha256)
    ):
        raise ValueError("current Greenhouse capture cannot bind to this attempt")
    token.consume(attempt_id)
    binding = dict(capture.market_binding)
    application_id = str(binding["application_id"])
    base = {
        "schema_version": "jaa.greenhouse-current-navigation-proof.v1",
        "authority_kind": "owned_current_navigation_observation",
        "attempt_id": attempt_id,
        "navigation_event_sha256": navigation_event_sha256,
        "application_id": application_id,
        "job_key": vacancy.job_key,
        "vacancy_sha256": vacancy.vacancy_sha256,
        "source_url": capture.source_url,
        "response_url": capture.response_url,
        "method": capture.method,
        "status": capture.status,
        "observed_at": capture.observed_at,
        "primary_response_sha256": capture.primary_response_sha256,
        "redacted_response_sha256": capture.redacted_response_sha256,
        "loader_config_sha256": capture.loader_config_sha256,
        "success_observation_sha256": _sha256(
            _bytes(
                {
                    "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
                    "provider": "greenhouse",
                    "observed_at": capture.observed_at,
                    "request": {
                        "method": capture.method,
                        "status": capture.status,
                        "url": capture.response_url,
                    },
                    "provider_loader_paths": {
                        "confirmationPath": capture.loader_document["confirmationPath"],
                        "confirmation_message": capture.loader_document["confirmation_message"],
                        "submitPath": capture.loader_document["submitPath"],
                    },
                    "interaction": {
                        "fields_filled": 0,
                        "files_uploaded": 0,
                        "submit_clicks": 0,
                    },
                }
            )
        ),
        "market_context_sha256": capture.market_context_sha256,
        "market_binding": binding,
        "repository_head": capture.repository_head,
        "code_source_sha256s": [
            {"path": path, "sha256": digest}
            for path, digest in capture.code_source_sha256s
        ],
        "release_authority": False,
        "submission_authority": False,
    }
    proof_sha256 = _sha256(_bytes(base))
    return CurrentGreenhouseNavigationProof(
        attempt_id=attempt_id,
        navigation_event_sha256=navigation_event_sha256,
        application_id=application_id,
        job_key=vacancy.job_key,
        vacancy_sha256=vacancy.vacancy_sha256,
        source_url=capture.source_url,
        response_url=capture.response_url,
        method=capture.method,
        status=capture.status,
        observed_at=capture.observed_at,
        primary_response_sha256=capture.primary_response_sha256,
        redacted_response_sha256=capture.redacted_response_sha256,
        loader_config_sha256=capture.loader_config_sha256,
        market_context_sha256=capture.market_context_sha256,
        market_binding=capture.market_binding,
        repository_head=capture.repository_head,
        code_source_sha256s=capture.code_source_sha256s,
        loader_config=capture.loader_config,
        redacted_response=capture.redacted_response,
        page_identity=capture.page_identity,
        proof_sha256=proof_sha256,
        _issuer=_PROOF_ISSUER,
    )


def reserve_current_greenhouse_navigation_capture(
    capture: CurrentGreenhouseNavigationCapture, *, attempt_id: str, page, vacancy
) -> None:
    token = _validate_capture_attempt_binding(
        capture, attempt_id=attempt_id, vacancy=vacancy
    )
    if capture.page_identity != id(page):
        raise ValueError("current navigation capture is not owned by this attempt")
    token.reserve(attempt_id)


def consume_current_greenhouse_navigation_capture(
    capture: CurrentGreenhouseNavigationCapture,
    *,
    attempt_id: str,
    page,
    vacancy,
) -> None:
    token = _validate_capture_attempt_binding(
        capture, attempt_id=attempt_id, vacancy=vacancy
    )
    if capture.page_identity != id(page):
        raise ValueError("current navigation capture is not owned by this attempt")
    token.consume(attempt_id)


def _validate_capture_attempt_binding(
    capture: CurrentGreenhouseNavigationCapture, *, attempt_id: str, vacancy
) -> _CaptureBindingToken:
    if (
        type(capture) is not CurrentGreenhouseNavigationCapture
        or capture._issuer is not _CAPTURE_ISSUER
        or type(capture._binding_token) is not _CaptureBindingToken
        or type(attempt_id) is not str
        or not attempt_id
    ):
        raise ValueError("current navigation capture is not owned by this attempt")
    binding = dict(capture.market_binding)
    application_id = str(binding.get("application_id", ""))
    if not application_id.startswith("app_"):
        raise ValueError("current Greenhouse capture lacks its admitted application")
    if (
        vacancy.source_url != capture.source_url
        or vacancy.vacancy_sha256 != binding.get("raw_listing_sha256")
        or vacancy.job_key != binding.get("source_job_key")
    ):
        raise ValueError("current Greenhouse capture cannot bind to this vacancy")
    return capture._binding_token


def verify_live_current_greenhouse_navigation(
    proof: CurrentGreenhouseNavigationProof,
    *,
    context,
    page,
    attempt_id: str,
    vacancy,
) -> None:
    if type(proof) is not CurrentGreenhouseNavigationProof or proof._issuer is not _PROOF_ISSUER:
        raise ValueError("current Greenhouse navigation proof is not owner-issued")
    binding = _context_binding(context)
    if (
        _sha256(canonical_json(binding).encode("utf-8"))
        != proof.market_context_sha256
        or tuple(sorted(binding.items())) != proof.market_binding
        or proof.page_identity != id(page)
        or proof.attempt_id != attempt_id
        or proof.source_url != vacancy.source_url
        or proof.job_key != vacancy.job_key
        or proof.vacancy_sha256 != vacancy.vacancy_sha256
    ):
        raise ValueError("current Greenhouse navigation differs from live admission")


def verify_current_greenhouse_navigation_proof(
    proof: CurrentGreenhouseNavigationProof,
    *,
    source_url: str,
    application_id: str,
    job_key: str,
    vacancy_sha256: str,
    attempt_id: str,
    repository_root: str | Path,
    success_observation: bytes,
    archived_response: bytes,
    archived_loader_config: bytes,
    navigation_event: Mapping[str, object],
    page=None,
) -> dict[str, object]:
    if type(proof) is not CurrentGreenhouseNavigationProof or proof._issuer is not _PROOF_ISSUER:
        raise ValueError("current Greenhouse navigation proof is not owner-issued")
    document = proof.document()
    event_payload = navigation_event.get("payload")
    event_details = (
        event_payload.get("details") if isinstance(event_payload, Mapping) else None
    )
    event_members = (
        event_payload.get("member_sha256s")
        if isinstance(event_payload, Mapping)
        else None
    )
    expected_config = proof.loader_config
    if (
        proof.attempt_id != attempt_id
        or proof.application_id != application_id
        or proof.job_key != job_key
        or proof.vacancy_sha256 != vacancy_sha256
        or proof.source_url != source_url
        or proof.response_url != source_url
        or proof.method != "GET"
        or type(proof.status) is not int
        or not 200 <= proof.status < 300
        or _sha256(success_observation) != document["success_observation_sha256"]
        or success_observation != proof.observation_bytes()
        or _sha256(archived_response) != proof.redacted_response_sha256
        or archived_response != proof.redacted_response
        or _sha256(archived_loader_config) != proof.loader_config_sha256
        or archived_loader_config != expected_config
        or not isinstance(event_payload, Mapping)
        or event_payload.get("event_kind") != "navigation"
        or not isinstance(event_details, Mapping)
        or event_details.get("provider_response_sha256")
        != proof.primary_response_sha256
        or event_details.get("provider_loader_config_sha256")
        != proof.loader_config_sha256
        or not isinstance(event_members, Mapping)
        or event_members.get("provider.current_loader_config")
        != proof.loader_config_sha256
        or navigation_event.get("event_sha256") != proof.navigation_event_sha256
        or (page is not None and id(page) != proof.page_identity)
    ):
        raise ValueError("current Greenhouse navigation proof binding differs")
    binding = dict(proof.market_binding)
    if (
        binding.get("application_id") != application_id
        or binding.get("source_job_key") != job_key
        or binding.get("source_url") != source_url
        or binding.get("raw_listing_sha256") != vacancy_sha256
    ):
        raise ValueError("current Greenhouse Market binding differs")
    head, source_hashes = _code_identity(repository_root)
    if head != proof.repository_head or source_hashes != proof.code_source_sha256s:
        raise ValueError("current Greenhouse proof source revision changed")
    parsed = parse_current_greenhouse_loader(
        archived_response, source_url=source_url
    )
    parsed_document = _loader_document(parsed)
    if parsed_document != proof.loader_document():
        raise ValueError("archived current Greenhouse response no longer parses")
    return document


__all__ = [
    "CurrentGreenhouseNavigationCapture",
    "CurrentGreenhouseNavigationProof",
    "bind_current_greenhouse_navigation",
    "capture_current_greenhouse_navigation",
    "consume_current_greenhouse_navigation_capture",
    "reserve_current_greenhouse_navigation_capture",
    "verify_current_greenhouse_navigation_proof",
    "verify_live_current_greenhouse_navigation",
]
