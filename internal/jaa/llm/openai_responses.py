"""Exact, opt-in OpenAI Responses transport for structured JAA reviews.

This module is a provider adapter beneath the canonical :mod:`llm.client`
boundary.  It does not own application policy, receipt issuance, release,
browser authority, or a second employer-review workflow.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

import requests

from .client import Backend, LLMError, LLMResponse, validate_json


OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
OPENAI_PROVIDER_IDENTITY = "openai.responses-api"
OPENAI_API_VERSION = "2020-10-01"
OPENAI_TRANSPORT_VERSION = (
    f"requests/{requests.__version__};openai-api/{OPENAI_API_VERSION};responses/v1"
)
OPENAI_RESPONSE_EVIDENCE_SCHEMA = "jaa.llm.openai-response-evidence.v1"
PROVIDER_SCHEMA_PROJECTION_ID = "openai.structured-output-subset.v1"
_USER_AGENT = "market-aligner-jaa/1"
_MAX_BODY_BYTES = 2_000_000
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_FORMAT_NAME = re.compile(r"[^A-Za-z0-9_-]+")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_json_object(value: bytes, *, label: str) -> dict[str, Any]:
    if not isinstance(value, bytes) or not value or len(value) > _MAX_BODY_BYTES:
        raise RuntimeError(f"{label} is empty or oversized")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{label} is not UTF-8") from exc

    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in rows:
            if key in result:
                raise RuntimeError(f"{label} contains duplicate JSON keys")
            result[key] = item
        return result

    def constant(_: str) -> object:
        raise RuntimeError(f"{label} contains a non-finite JSON number")

    try:
        document = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not one JSON object") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{label} is not one JSON object")
    return document


def _endpoint_transport_identity(endpoint: str) -> str:
    return f"openai.responses.https@sha256:{_sha256(endpoint.encode())}"


@dataclass(frozen=True)
class OpenAIResponsesConfig:
    """Frozen non-secret endpoint/model settings plus one credential seam."""

    requested_model: str
    api_key_environment_variable: str = "OPENAI_API_KEY"
    timeout_seconds: int = 90
    endpoint: str = OPENAI_RESPONSES_ENDPOINT

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if (
            self.endpoint != OPENAI_RESPONSES_ENDPOINT
            or parsed.scheme != "https"
            or parsed.hostname != "api.openai.com"
            or parsed.port not in {None, 443}
            or parsed.path != "/v1/responses"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("endpoint must be the exact OpenAI Responses URL")
        if not _MODEL_NAME.fullmatch(self.requested_model):
            raise ValueError("requested OpenAI model identity is malformed")
        if not _ENV_NAME.fullmatch(self.api_key_environment_variable):
            raise ValueError("credential environment-variable name is malformed")
        if (
            isinstance(self.timeout_seconds, bool)
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 300
        ):
            raise ValueError("OpenAI timeout must be 1..300 seconds")

    @property
    def endpoint_sha256(self) -> str:
        return _sha256(self.endpoint.encode())


def openai_provider_response_schema(value: Mapping[str, object]) -> dict[str, object]:
    """Project only a known unsupported keyword; local validation stays whole."""

    def project(item: object) -> object:
        if isinstance(item, Mapping):
            return {
                str(key): project(child)
                for key, child in item.items()
                if key != "uniqueItems"
            }
        if isinstance(item, list):
            return [project(child) for child in item]
        return item

    projected = project(value)
    if not isinstance(projected, dict):
        raise ValueError("provider response schema must remain an object")
    return projected


def _format_name(task: str) -> str:
    value = _FORMAT_NAME.sub("_", str(task)).strip("_-") or "structured_output"
    return value[:64]


def openai_request_document(
    *,
    system: str,
    user: str,
    requested_model: str,
    temperature: float,
    schema: Mapping[str, object],
    task: str,
) -> dict[str, object]:
    """Build the complete tool-free, stateless structured-output request."""

    if not isinstance(system, str) or not isinstance(user, str):
        raise TypeError("OpenAI prompts must be text")
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
        raise ValueError("OpenAI temperature must be numeric")
    return {
        "input": [
            {
                "content": [{"text": system, "type": "input_text"}],
                "role": "system",
            },
            {
                "content": [{"text": user, "type": "input_text"}],
                "role": "user",
            },
        ],
        "model": requested_model,
        "store": False,
        "stream": False,
        "temperature": float(temperature),
        "text": {
            "format": {
                "name": _format_name(task),
                "schema": openai_provider_response_schema(schema),
                "strict": True,
                "type": "json_schema",
            }
        },
        "tool_choice": "none",
        "tools": [],
    }


def openai_request_bytes(**values: object) -> bytes:
    payload = _canonical_json(openai_request_document(**values)).encode()
    if not payload or len(payload) > _MAX_BODY_BYTES:
        raise RuntimeError("OpenAI request body is empty or oversized")
    return payload


def _response_output(
    document: Mapping[str, object], *, requested_model: str, schema: dict[str, Any]
) -> tuple[str, str, int, int]:
    if (
        document.get("object") != "response"
        or document.get("status") != "completed"
        or document.get("error") is not None
        or document.get("incomplete_details") is not None
        or document.get("model") != requested_model
    ):
        raise RuntimeError("OpenAI response status or actual model disagrees")
    response_id = document.get("id")
    output = document.get("output")
    if not isinstance(response_id, str) or not response_id.strip():
        raise RuntimeError("OpenAI response lacks its provider response ID")
    if not isinstance(output, list):
        raise RuntimeError("OpenAI response output is malformed")
    messages: list[Mapping[str, object]] = []
    for item in output:
        if not isinstance(item, Mapping):
            raise RuntimeError("OpenAI response output item is malformed")
        if item.get("type") == "reasoning":
            continue
        if item.get("type") != "message":
            raise RuntimeError("OpenAI response attempted a non-message output")
        messages.append(item)
    if len(messages) != 1:
        raise RuntimeError("OpenAI response must contain one assistant message")
    message = messages[0]
    if message.get("role") != "assistant" or message.get("status") != "completed":
        raise RuntimeError("OpenAI assistant message is incomplete")
    content = message.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise RuntimeError("OpenAI assistant message must contain one output item")
    item = content[0]
    if not isinstance(item, Mapping) or item.get("type") != "output_text":
        raise RuntimeError("OpenAI assistant refused or changed output type")
    text = item.get("text")
    if not isinstance(text, str) or not text:
        raise RuntimeError("OpenAI assistant output text is empty")
    semantic = _strict_json_object(text.encode(), label="OpenAI structured output")
    validate_json(semantic, schema)

    usage = document.get("usage")
    prompt_tokens = 0
    completion_tokens = 0
    if usage is not None:
        if not isinstance(usage, Mapping):
            raise RuntimeError("OpenAI response usage is malformed")
        prompt_tokens = usage.get("input_tokens", 0)  # type: ignore[assignment]
        completion_tokens = usage.get("output_tokens", 0)  # type: ignore[assignment]
        if (
            isinstance(prompt_tokens, bool)
            or not isinstance(prompt_tokens, int)
            or prompt_tokens < 0
            or isinstance(completion_tokens, bool)
            or not isinstance(completion_tokens, int)
            or completion_tokens < 0
        ):
            raise RuntimeError("OpenAI response usage is malformed")
    return _canonical_json(semantic), response_id, prompt_tokens, completion_tokens


def _assert_prepared_request(
    prepared: requests.PreparedRequest,
    *,
    endpoint: str,
    request_bytes: bytes,
    authorization: str,
    client_request_id: str,
) -> None:
    if not isinstance(prepared, requests.PreparedRequest):
        raise RuntimeError("OpenAI transport did not prepare an exact request")
    if (
        prepared.method != "POST"
        or prepared.url != endpoint
        or prepared.body != request_bytes
        or prepared.headers.get("Content-Type") != "application/json"
        or prepared.headers.get("OpenAI-Version") != OPENAI_API_VERSION
        or prepared.headers.get("User-Agent") != _USER_AGENT
        or prepared.headers.get("Authorization") != authorization
        or prepared.headers.get("X-Client-Request-Id") != client_request_id
        or prepared.headers.get("Content-Length") != str(len(request_bytes))
    ):
        raise RuntimeError("OpenAI prepared request differs from frozen bytes")


class OpenAIResponsesBackend(Backend):
    """One exact HTTPS exchange for each provider-native structured call."""

    environment = "production"

    def __init__(self, config: OpenAIResponsesConfig) -> None:
        config.__post_init__()
        self.config = config
        self.name = _endpoint_transport_identity(config.endpoint)
        self.version = OPENAI_TRANSPORT_VERSION
        self._client_request_ids: set[str] = set()
        self._transport_request_ids: set[str] = set()
        self._provider_response_ids: set[str] = set()
        self._identity_lock = threading.Lock()

    def available(self) -> bool:
        value = os.environ.get(self.config.api_key_environment_variable, "")
        return bool(value and "\r" not in value and "\n" not in value)

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        raise LLMError(
            "OpenAIResponsesBackend requires the structured-output client seam"
        )

    def complete_structured(
        self,
        system: str,
        user: str,
        temperature: float,
        *,
        schema: dict[str, Any],
        task: str,
    ) -> LLMResponse:
        self.config.__post_init__()
        request_bytes = openai_request_bytes(
            system=system,
            user=user,
            requested_model=self.config.requested_model,
            temperature=temperature,
            schema=schema,
            task=task,
        )
        api_key = os.environ.get(self.config.api_key_environment_variable, "")
        if not api_key or "\r" in api_key or "\n" in api_key:
            raise LLMError("OpenAI credential is unavailable")
        authorization = f"Bearer {api_key}"
        client_request_id = str(uuid.uuid4())
        self._claim_identity(self._client_request_ids, client_request_id, "client")
        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json",
            "OpenAI-Version": OPENAI_API_VERSION,
            "User-Agent": _USER_AGENT,
            "X-Client-Request-Id": client_request_id,
        }
        session = requests.Session()
        session.trust_env = False
        prepared: requests.PreparedRequest | None = None
        response: requests.Response | None = None
        try:
            request = requests.Request(
                method="POST",
                url=self.config.endpoint,
                data=request_bytes,
                headers=headers,
            )
            prepared = session.prepare_request(request)
            _assert_prepared_request(
                prepared,
                endpoint=self.config.endpoint,
                request_bytes=request_bytes,
                authorization=authorization,
                client_request_id=client_request_id,
            )
            response = session.send(
                prepared,
                timeout=self.config.timeout_seconds,
                allow_redirects=False,
            )
            response_bytes = bytes(response.content)
            if response.request is not prepared:
                raise RuntimeError("OpenAI response is not bound to its request")
            _assert_prepared_request(
                response.request,
                endpoint=self.config.endpoint,
                request_bytes=request_bytes,
                authorization=authorization,
                client_request_id=client_request_id,
            )
            if (
                response.history
                or response.url != self.config.endpoint
                or response.is_redirect
                or response.is_permanent_redirect
                or response.status_code != 200
            ):
                raise RuntimeError("OpenAI HTTP exchange was not exact")
            request_id = response.headers.get("x-request-id", "")
            api_version = response.headers.get("openai-version", "")
            if not request_id.strip() or api_version != OPENAI_API_VERSION:
                raise RuntimeError("OpenAI response transport identity is absent")
            document = _strict_json_object(
                response_bytes, label="OpenAI response body"
            )
            text, response_id, prompt_tokens, completion_tokens = _response_output(
                document,
                requested_model=self.config.requested_model,
                schema=schema,
            )
            self._claim_identity(self._transport_request_ids, request_id, "provider request")
            self._claim_identity(
                self._provider_response_ids, response_id, "provider response"
            )
            evidence = {
                "schema_version": OPENAI_RESPONSE_EVIDENCE_SCHEMA,
                "provider_identity": OPENAI_PROVIDER_IDENTITY,
                "model_identity": str(document["model"]),
                "endpoint_sha256": self.config.endpoint_sha256,
                "transport_identity": self.name,
                "transport_version": self.version,
                "client_request_id": client_request_id,
                "transport_request_id": request_id,
                "provider_response_id": response_id,
                "request_sha256": _sha256(request_bytes),
                "response_sha256": _sha256(response_bytes),
                "semantic_output_sha256": _sha256(text.encode()),
            }
            return LLMResponse(
                text=text,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                model=str(document["model"]),
                transport_evidence=evidence,
                private_transport_payload={
                    "request": request_bytes,
                    "response": response_bytes,
                },
            )
        except requests.RequestException as exc:
            raise RuntimeError("OpenAI Responses transport failed") from exc
        finally:
            api_key = ""
            authorization = ""
            headers.clear()
            if prepared is not None:
                prepared.headers.pop("Authorization", None)
            if response is not None and isinstance(
                getattr(response, "request", None), requests.PreparedRequest
            ):
                response.request.headers.pop("Authorization", None)
            session.close()

    def _claim_identity(self, store: set[str], value: str, label: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"OpenAI {label} identity is absent")
        with self._identity_lock:
            if value in store:
                raise RuntimeError(f"OpenAI {label} identity was reused")
            store.add(value)

    def safe_configuration_document(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.llm.openai-responses-config.v1",
            "endpoint_sha256": self.config.endpoint_sha256,
            "requested_model": self.config.requested_model,
            "provider_identity": OPENAI_PROVIDER_IDENTITY,
            "provider_schema_projection_id": PROVIDER_SCHEMA_PROJECTION_ID,
            "transport_identity": self.name,
            "transport_version": self.version,
        }


__all__ = [
    "OPENAI_API_VERSION",
    "OPENAI_PROVIDER_IDENTITY",
    "OPENAI_RESPONSES_ENDPOINT",
    "OPENAI_RESPONSE_EVIDENCE_SCHEMA",
    "OPENAI_TRANSPORT_VERSION",
    "PROVIDER_SCHEMA_PROJECTION_ID",
    "OpenAIResponsesBackend",
    "OpenAIResponsesConfig",
    "openai_provider_response_schema",
    "openai_request_bytes",
    "openai_request_document",
]
