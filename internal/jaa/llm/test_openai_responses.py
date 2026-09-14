from __future__ import annotations

import json
import stat
from copy import deepcopy

import pytest
import requests

from llm import openai_responses as provider_module
from llm.client import LLMClient, LLMError, make_backend
from llm.openai_responses import (
    OPENAI_API_VERSION,
    OPENAI_PROVIDER_IDENTITY,
    OPENAI_RESPONSES_ENDPOINT,
    OPENAI_RESPONSE_EVIDENCE_SCHEMA,
    OpenAIResponsesBackend,
    OpenAIResponsesConfig,
    openai_provider_response_schema,
    openai_request_document,
)


MODEL = "gpt-5-2025-08-07"
KEY_ENV = "JAA_TEST_OPENAI_API_KEY"
SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "codes"],
    "properties": {
        "verdict": {"enum": ["pass", "block"]},
        "codes": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string"},
        },
    },
}


class FakeResponse:
    def __init__(
        self,
        *,
        document: dict[str, object] | None = None,
        status_code: int = 200,
        url: str = OPENAI_RESPONSES_ENDPOINT,
        request_id: str = "req_test_1",
        api_version: str = OPENAI_API_VERSION,
        redirect: bool = False,
    ) -> None:
        result = json.dumps(
            {"codes": [], "verdict": "pass"},
            separators=(",", ":"),
            sort_keys=True,
        )
        self.document = document or {
            "error": None,
            "id": "resp_test_1",
            "incomplete_details": None,
            "model": MODEL,
            "object": "response",
            "output": [
                {"id": "reasoning_1", "type": "reasoning"},
                {
                    "content": [
                        {"annotations": [], "text": result, "type": "output_text"}
                    ],
                    "id": "message_1",
                    "role": "assistant",
                    "status": "completed",
                    "type": "message",
                },
            ],
            "status": "completed",
            "usage": {"input_tokens": 13, "output_tokens": 7},
        }
        self.content = json.dumps(self.document, separators=(",", ":")).encode()
        self.status_code = status_code
        self.url = url
        self.headers = {
            "x-request-id": request_id,
            "openai-version": api_version,
        }
        self.history: list[object] = []
        self.is_redirect = redirect
        self.is_permanent_redirect = redirect
        self.request = None


class FakeSession:
    responses: list[FakeResponse] = []
    calls: list[dict[str, object]] = []
    prepare_mutator = None
    response_request_mutator = None

    def __init__(self) -> None:
        self.trust_env = True
        self.closed = False

    def prepare_request(self, request: requests.Request):
        prepared = request.prepare()
        if type(self).prepare_mutator is not None:
            type(self).prepare_mutator(prepared)
        return prepared

    def send(self, prepared, **kwargs: object) -> FakeResponse:
        type(self).calls.append(
            {
                "body": prepared.body,
                "content_type": prepared.headers.get("Content-Type"),
                "method": prepared.method,
                "openai_version": prepared.headers.get("OpenAI-Version"),
                "client_request_id": prepared.headers.get("X-Client-Request-Id"),
                "trust_env": self.trust_env,
                "url": prepared.url,
                "user_agent": prepared.headers.get("User-Agent"),
                **kwargs,
            }
        )
        if not type(self).responses:
            raise AssertionError("fake response queue is empty")
        response = type(self).responses.pop(0)
        response.request = prepared
        if type(self).response_request_mutator is not None:
            type(self).response_request_mutator(response.request)
        return response

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def fake_transport(monkeypatch: pytest.MonkeyPatch):
    FakeSession.responses = []
    FakeSession.calls = []
    FakeSession.prepare_mutator = None
    FakeSession.response_request_mutator = None
    monkeypatch.setattr(provider_module.requests, "Session", FakeSession)
    monkeypatch.setenv(KEY_ENV, "test-secret-never-retained")


def backend() -> OpenAIResponsesBackend:
    return OpenAIResponsesBackend(
        OpenAIResponsesConfig(
            requested_model=MODEL,
            api_key_environment_variable=KEY_ENV,
        )
    )


def client(selected: OpenAIResponsesBackend, tmp_path) -> LLMClient:
    return LLMClient(
        backend=selected,
        model=MODEL,
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / "cache",
        transport_archive_dir=tmp_path / "provider-exchanges",
        usage_log=tmp_path / "usage.jsonl",
    )


def test_exact_tool_free_one_shot_and_evidence_binding(tmp_path) -> None:
    FakeSession.responses = [FakeResponse()]
    selected = backend()
    result, response = client(selected, tmp_path).complete_json_with_response(
        "policy",
        '{"quoted":"input"}',
        schema=SCHEMA,
        task="application_sanity_review",
        json_attempts=1,
    )
    assert result == {"codes": [], "verdict": "pass"}
    assert response.model == MODEL
    assert response.prompt_tokens == 13
    assert response.completion_tokens == 7
    assert response.transport_evidence is not None
    evidence = response.transport_evidence
    assert evidence["schema_version"] == OPENAI_RESPONSE_EVIDENCE_SCHEMA
    assert evidence["provider_identity"] == OPENAI_PROVIDER_IDENTITY
    assert evidence["model_identity"] == MODEL
    assert evidence["transport_request_id"] == "req_test_1"
    assert evidence["provider_response_id"] == "resp_test_1"
    exchange_dir = tmp_path / "provider-exchanges" / evidence["client_request_id"]
    assert exchange_dir.joinpath("request.json").read_bytes() == FakeSession.calls[0][
        "body"
    ]
    assert evidence["response_sha256"] == provider_module._sha256(
        exchange_dir.joinpath("response.json").read_bytes()
    )
    assert evidence["archive_manifest_sha256"] == provider_module._sha256(
        exchange_dir.joinpath("manifest.json").read_bytes()
    )
    assert stat.S_IMODE(exchange_dir.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in exchange_dir.iterdir()
    )
    assert len(FakeSession.calls) == 1
    call = FakeSession.calls[0]
    assert call["url"] == OPENAI_RESPONSES_ENDPOINT
    assert call["allow_redirects"] is False
    assert call["trust_env"] is False
    assert call["method"] == "POST"
    assert call["content_type"] == "application/json"
    assert call["openai_version"] == OPENAI_API_VERSION
    assert call["user_agent"] == "market-aligner-jaa/1"
    assert call["client_request_id"] == evidence["client_request_id"]
    body = json.loads(call["body"])
    expected = openai_request_document(
        system=(
            "policy\n\nREQUIRED OUTPUT CONTRACT (JSON Schema):\n"
            + json.dumps(SCHEMA, ensure_ascii=False, sort_keys=True)
            + "\nReturn one JSON object satisfying this contract exactly. "
            "Do not rename keys or add properties."
        ),
        user='{"quoted":"input"}',
        requested_model=MODEL,
        temperature=0,
        schema=SCHEMA,
        task="application_sanity_review",
    )
    assert body == expected
    assert body["store"] is False
    assert body["stream"] is False
    assert body["tools"] == []
    assert body["tool_choice"] == "none"
    provider_schema = body["text"]["format"]["schema"]
    assert provider_schema == openai_provider_response_schema(SCHEMA)
    assert "uniqueItems" not in json.dumps(provider_schema)
    assert "uniqueItems" in json.dumps(SCHEMA)
    encoded = call["body"].decode()
    assert KEY_ENV not in encoded
    assert "test-secret-never-retained" not in encoded
    safe = json.dumps(selected.safe_configuration_document(), sort_keys=True)
    assert KEY_ENV not in safe
    assert "test-secret-never-retained" not in safe


def _mutate_prepared_request(prepared, field: str) -> None:
    if field == "method":
        prepared.method = "GET"
    elif field == "url":
        prepared.url = "https://api.openai.com/v1/responses?mutated=1"
    elif field == "body":
        prepared.body = b"{}"
        prepared.headers["Content-Length"] = "2"
    elif field == "content_type":
        prepared.headers["Content-Type"] = "text/plain"
    elif field == "api_version":
        prepared.headers["OpenAI-Version"] = "stale"
    elif field == "user_agent":
        prepared.headers["User-Agent"] = "mutated-client/1"
    elif field == "client_request_id":
        prepared.headers["X-Client-Request-Id"] = "mutated"
    else:  # pragma: no cover
        raise AssertionError(field)


@pytest.mark.parametrize(
    "field",
    (
        "method",
        "url",
        "body",
        "content_type",
        "api_version",
        "user_agent",
        "client_request_id",
    ),
)
def test_prepared_request_mutation_fails_before_send(tmp_path, field: str) -> None:
    FakeSession.responses = [FakeResponse()]
    FakeSession.prepare_mutator = lambda prepared: _mutate_prepared_request(
        prepared, field
    )
    with pytest.raises(LLMError, match="structured backend failed"):
        client(backend(), tmp_path).complete_json(
            "policy", "{}", schema=SCHEMA, json_attempts=1
        )
    assert FakeSession.calls == []


@pytest.mark.parametrize(
    "field",
    (
        "method",
        "url",
        "body",
        "content_type",
        "api_version",
        "user_agent",
        "client_request_id",
    ),
)
def test_response_request_mutation_fails_after_send(tmp_path, field: str) -> None:
    FakeSession.responses = [FakeResponse()]
    FakeSession.response_request_mutator = lambda prepared: _mutate_prepared_request(
        prepared, field
    )
    with pytest.raises(LLMError, match="structured backend failed"):
        client(backend(), tmp_path).complete_json(
            "policy", "{}", schema=SCHEMA, json_attempts=1
        )
    assert len(FakeSession.calls) == 1


@pytest.mark.parametrize(
    "response",
    (
        FakeResponse(status_code=307, redirect=True),
        FakeResponse(url="https://example.test/v1/responses"),
        FakeResponse(request_id=""),
        FakeResponse(api_version="stale"),
        FakeResponse(
            document={
                "error": None,
                "id": "resp_wrong_model",
                "incomplete_details": None,
                "model": "other-model",
                "object": "response",
                "output": [],
                "status": "completed",
            }
        ),
        FakeResponse(
            document={
                "error": None,
                "id": "resp_tool",
                "incomplete_details": None,
                "model": MODEL,
                "object": "response",
                "output": [{"type": "web_search_call"}],
                "status": "completed",
            }
        ),
    ),
)
def test_redirect_identity_model_and_tool_output_fail_closed(
    tmp_path, response: FakeResponse
) -> None:
    FakeSession.responses = [deepcopy(response)]
    with pytest.raises(LLMError, match="structured backend failed"):
        client(backend(), tmp_path).complete_json(
            "policy", "{}", schema=SCHEMA, json_attempts=1
        )


@pytest.mark.parametrize(
    "invalid_text",
    (
        '{"codes":[],"verdict":"pass","verdict":"block"}',
        '{"codes":[],"verdict":NaN}',
        '{"codes":[],"verdict":"uncertain"}',
    ),
)
def test_duplicate_nonfinite_and_schema_invalid_output_fail_closed(
    tmp_path, invalid_text: str
) -> None:
    response = FakeResponse()
    response.document["output"][1]["content"][0]["text"] = invalid_text
    response.content = json.dumps(response.document, separators=(",", ":")).encode()
    FakeSession.responses = [response]
    with pytest.raises(LLMError, match="structured backend failed|not in enum"):
        client(backend(), tmp_path).complete_json(
            "policy", "{}", schema=SCHEMA, json_attempts=1
        )


def test_missing_credential_and_reused_provider_ids_fail_closed(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = backend()
    monkeypatch.delenv(KEY_ENV)
    assert selected.available() is False
    with pytest.raises(LLMError, match="credential"):
        client(selected, tmp_path).complete_json(
            "policy", "{}", schema=SCHEMA, json_attempts=1
        )

    monkeypatch.setenv(KEY_ENV, "test-secret-never-retained")
    FakeSession.responses = [FakeResponse(), FakeResponse()]
    selected = backend()
    client(selected, tmp_path / "first").complete_json(
        "policy", "one", schema=SCHEMA, json_attempts=1
    )
    with pytest.raises(LLMError, match="reused"):
        client(selected, tmp_path / "second").complete_json(
            "policy", "two", schema=SCHEMA, json_attempts=1
        )


def test_exact_transport_bytes_require_private_archive(tmp_path) -> None:
    FakeSession.responses = [FakeResponse()]
    selected = backend()
    runtime = LLMClient(
        backend=selected,
        model=MODEL,
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / "cache",
        usage_log=tmp_path / "usage.jsonl",
    )
    with pytest.raises(LLMError, match="private archive directory"):
        runtime.complete_json("policy", "{}", schema=SCHEMA, json_attempts=1)


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://api.openai.com/v1/responses",
        "https://example.test/v1/responses",
        "https://api.openai.com/v1/responses?redirect=1",
        "https://api.openai.com:444/v1/responses",
        "https://user@api.openai.com/v1/responses",
        "https://api.openai.com/v1/chat/completions",
    ),
)
def test_endpoint_substitution_fails(endpoint: str) -> None:
    with pytest.raises(ValueError, match="exact OpenAI Responses"):
        OpenAIResponsesConfig(
            endpoint=endpoint,
            requested_model=MODEL,
            api_key_environment_variable=KEY_ENV,
        )


def test_unstructured_seam_is_refused() -> None:
    with pytest.raises(LLMError, match="structured-output"):
        backend().complete("policy", "{}", 0)


def test_backend_selector_is_explicit_and_configuration_is_redacted() -> None:
    selected = make_backend(
        {
            "backend": "openai_responses",
            "openai_model": MODEL,
            "openai_api_key_env": KEY_ENV,
            "openai_timeout_seconds": 37,
        }
    )
    assert isinstance(selected, OpenAIResponsesBackend)
    assert selected.config.requested_model == MODEL
    assert selected.config.timeout_seconds == 37
    safe = json.dumps(selected.safe_configuration_document(), sort_keys=True)
    assert KEY_ENV not in safe
    assert "test-secret-never-retained" not in safe
