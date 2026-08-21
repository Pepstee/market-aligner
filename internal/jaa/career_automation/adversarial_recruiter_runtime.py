"""One-shot isolated Codex transport for detached recruiter assessments.

This runtime is intentionally separate from the general Codex backend.  It
starts a fresh ephemeral process in a request-only temporary directory,
allows one invocation, rejects observed tool activity, and emits hash-bound
transport evidence alongside the diagnostic assessment.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from llm.client import Backend, LLMClient, LLMError, LLMResponse

from .adversarial_recruiter import (
    RESULT_SCHEMA,
    RecruiterAssessmentPackage,
    RecruiterAssessmentReceipt,
    assess_application_as_recruiter,
)
from .evidence_matching import canonical_json, content_hash


RUNTIME_SCHEMA_VERSION = "jaa.detached-recruiter-runtime.v1"
PROVIDER_IDENTITY = "openai-codex-cli"
_ENV_ALLOWLIST = frozenset(
    {
        "ALL_PROXY",
        "CODEX_HOME",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
    }
)
_DISABLED_FEATURES = (
    "apps",
    "browser_use",
    "computer_use",
    "image_generation",
    "in_app_browser",
    "multi_agent",
    "multi_agent_v2",
    "plugins",
    "remote_plugin",
    "shell_tool",
    "skill_search",
    "unified_exec",
    "workspace_dependencies",
)
_ALLOWED_ITEM_TYPES = frozenset({"agent_message", "reasoning"})


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _scrubbed_environment(source: Mapping[str, str]) -> dict[str, str]:
    env = {key: value for key, value in source.items() if key in _ENV_ALLOWLIST}
    if "CODEX_HOME" not in env and "HOME" in env:
        env["CODEX_HOME"] = str(Path(env["HOME"]) / ".codex")
    return env


def _reject_tool_events(stdout: str) -> None:
    for raw in stdout.splitlines():
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMError("codex JSONL transport returned malformed event data") from exc
        if not isinstance(event, dict):
            raise LLMError("codex JSONL transport returned a non-object event")
        item = event.get("item")
        if isinstance(item, dict):
            item_type = item.get("type")
            if item_type is not None and item_type not in _ALLOWED_ITEM_TYPES:
                raise LLMError(f"detached recruiter attempted forbidden tool item: {item_type}")


@dataclass(frozen=True)
class DetachedTransportReceipt:
    provider_identity: str
    provider_sha256: str
    model_identity: str
    model_sha256: str
    transport_sha256: str
    request_sha256: str
    response_sha256: str
    binary_sha256: str
    invocation_count: int
    receipt_sha256: str
    schema_version: str = RUNTIME_SCHEMA_VERSION

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": self.schema_version,
            "provider_identity": self.provider_identity,
            "provider_sha256": self.provider_sha256,
            "model_identity": self.model_identity,
            "model_sha256": self.model_sha256,
            "transport_sha256": self.transport_sha256,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "binary_sha256": self.binary_sha256,
            "invocation_count": self.invocation_count,
            "cache_enabled": False,
            "history_enabled": False,
            "tools_enabled": False,
            "retrieval_enabled": False,
        }
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value

    def __post_init__(self) -> None:
        if self.invocation_count != 1:
            raise ValueError("detached transport must contain exactly one invocation")
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise ValueError("detached transport receipt identity is invalid")


@dataclass(frozen=True)
class DetachedRecruiterRun:
    assessment: RecruiterAssessmentReceipt
    transport: DetachedTransportReceipt


class DetachedCodexRecruiterBackend(Backend):
    """Codex CLI backend with a request-scoped, no-history execution boundary."""

    name = "detached_codex_cli"

    def __init__(
        self,
        *,
        model: str,
        cli_timeout_seconds: float = 120.0,
        codex_binary: str | None = None,
        environment: Mapping[str, str] | None = None,
        codex_binary_fd: int | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("detached recruiter requires an explicit model")
        self.model = model.strip()
        self.cli_timeout_seconds = float(cli_timeout_seconds)
        self.codex_binary = codex_binary
        self.codex_binary_fd = codex_binary_fd
        self.environment = dict(os.environ if environment is None else environment)
        self.invocation_count = 0
        self.transport_receipt: DetachedTransportReceipt | None = None

    def _binary(self) -> str | None:
        if self.codex_binary_fd is not None:
            return f"/proc/self/fd/{self.codex_binary_fd}"
        return self.codex_binary or shutil.which("codex", path=self.environment.get("PATH"))

    def available(self) -> bool:
        return self._binary() is not None

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        if self.invocation_count:
            raise LLMError("detached recruiter backend is single-use")
        self.invocation_count += 1
        codex = self._binary()
        if codex is None:
            raise LLMError("codex CLI is unavailable")
        prompt = f"{system}\n\n{user}" if system else user
        binary_sha256 = _sha256_bytes(Path(codex).read_bytes())
        env = _scrubbed_environment(self.environment)

        with tempfile.TemporaryDirectory(prefix="jaa-recruiter-request-") as request_dir, tempfile.TemporaryDirectory(
            prefix="jaa-recruiter-response-"
        ) as response_dir:
            request_root = Path(request_dir)
            request_path = request_root / "request.prompt.txt"
            schema_path = request_root / "response.schema.json"
            output_path = Path(response_dir) / "last-message.json"
            request_path.write_text(prompt, encoding="utf-8")
            schema_path.write_text(canonical_json(RESULT_SCHEMA), encoding="utf-8")
            cmd = [
                codex,
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "-s",
                "read-only",
                "-C",
                request_dir,
                "--json",
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(output_path),
            ]
            for feature in _DISABLED_FEATURES:
                cmd.extend(("--disable", feature))
            cmd.extend(("-m", self.model, "-"))
            transport_document = {
                "provider": PROVIDER_IDENTITY,
                "argv_policy": cmd[1:],
                "environment_names": sorted(env),
                "cwd_policy": "fresh-request-material-only",
                "stdin_policy": "exact-request",
                "single_attempt": True,
            }
            try:
                proc = subprocess.run(
                    cmd,
                    input=prompt,
                    capture_output=True,
                    text=True,
                    timeout=self.cli_timeout_seconds,
                    cwd=request_dir,
                    env=env,
                    pass_fds=(
                        ()
                        if self.codex_binary_fd is None
                        else (self.codex_binary_fd,)
                    ),
                )
            except subprocess.TimeoutExpired as exc:
                raise LLMError("detached recruiter codex invocation timed out") from exc
            except OSError as exc:
                raise LLMError(f"failed to launch detached recruiter codex CLI: {exc}") from exc
            if proc.returncode != 0:
                diagnostic = "\n".join(part.strip() for part in (proc.stderr, proc.stdout) if part)
                raise LLMError(
                    f"detached recruiter codex CLI exited {proc.returncode}: "
                    f"{diagnostic[:4000]}"
                )
            _reject_tool_events(proc.stdout or "")
            if not output_path.exists():
                raise LLMError("detached recruiter codex CLI returned no final message")
            response = output_path.read_text(encoding="utf-8").strip()
            if not response:
                raise LLMError("detached recruiter codex CLI returned an empty final message")

        preimage = {
            "schema_version": RUNTIME_SCHEMA_VERSION,
            "provider_identity": PROVIDER_IDENTITY,
            "provider_sha256": content_hash({"provider": PROVIDER_IDENTITY}),
            "model_identity": self.model,
            "model_sha256": content_hash({"model": self.model}),
            "transport_sha256": content_hash(transport_document),
            "request_sha256": _sha256_text(prompt),
            "response_sha256": _sha256_text(response),
            "binary_sha256": binary_sha256,
            "invocation_count": self.invocation_count,
            "cache_enabled": False,
            "history_enabled": False,
            "tools_enabled": False,
            "retrieval_enabled": False,
        }
        receipt = DetachedTransportReceipt(
            provider_identity=PROVIDER_IDENTITY,
            provider_sha256=str(preimage["provider_sha256"]),
            model_identity=self.model,
            model_sha256=str(preimage["model_sha256"]),
            transport_sha256=str(preimage["transport_sha256"]),
            request_sha256=str(preimage["request_sha256"]),
            response_sha256=str(preimage["response_sha256"]),
            binary_sha256=binary_sha256,
            invocation_count=self.invocation_count,
            receipt_sha256=content_hash(preimage),
        )
        self.transport_receipt = receipt
        return LLMResponse(text=response, model=self.model)


def run_detached_recruiter_assessment(
    package: RecruiterAssessmentPackage,
    *,
    model: str,
    cli_timeout_seconds: float = 120.0,
    codex_binary: str | None = None,
    codex_binary_fd: int | None = None,
) -> DetachedRecruiterRun:
    backend = DetachedCodexRecruiterBackend(
        model=model,
        cli_timeout_seconds=cli_timeout_seconds,
        codex_binary=codex_binary,
        codex_binary_fd=codex_binary_fd,
    )
    with tempfile.TemporaryDirectory(prefix="jaa-recruiter-client-") as client_dir:
        root = Path(client_dir)
        client = LLMClient(
            backend=backend,
            model=model,
            temperature=0,
            max_retries=1,
            cache_enabled=False,
            cache_dir=root / "disabled-cache",
            usage_log=root / "usage.jsonl",
        )
        assessment = assess_application_as_recruiter(package, client=client)
    if backend.transport_receipt is None:
        raise LLMError("detached recruiter transport produced no receipt")
    return DetachedRecruiterRun(assessment=assessment, transport=backend.transport_receipt)


def run_synthetic_recruiter_canary(
    package: RecruiterAssessmentPackage,
    *,
    model: str,
    cli_timeout_seconds: float = 120.0,
    codex_binary: str | None = None,
) -> DetachedRecruiterRun:
    """Run only a package explicitly marked as synthetic and non-candidate."""
    if not package.listing_text.startswith("[SYNTHETIC NON-CANDIDATE CANARY]"):
        raise ValueError("canary listing lacks the synthetic non-candidate marker")
    if not package.intended_vacancy.job_key.startswith("synthetic-canary:"):
        raise ValueError("canary vacancy identity is not synthetic")
    return run_detached_recruiter_assessment(
        package,
        model=model,
        cli_timeout_seconds=cli_timeout_seconds,
        codex_binary=codex_binary,
    )


__all__ = [
    "DetachedCodexRecruiterBackend",
    "DetachedRecruiterRun",
    "DetachedTransportReceipt",
    "run_detached_recruiter_assessment",
    "run_synthetic_recruiter_canary",
]
