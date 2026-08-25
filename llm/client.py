"""
llm/client.py — model-agnostic LLM client with pluggable backends.

Design (Architecture.md: "the LLM's non-determinism is sealed behind the LLM
module's interface — fixed prompts, JSON schemas, temp≈0, cached and versioned"):

  * Backends are swappable. `MockBackend` is deterministic and OFFLINE — no API
    key, no network — so every downstream module and this module's own tests run
    reproducibly. `StubBackend` is the real-provider shape: reads a key from env,
    marked `# TODO wire provider`, and refuses to run until wired.
  * Retries with exponential backoff on transient backend errors.
  * A response CACHE keyed by sha256(prompt + input) under llm/data/cache/. A
    cache HIT never touches the backend (the tests assert exactly this).
  * A usage/cost log appended to llm/data/usage.jsonl (one JSON object per call).
  * Temperature read from skeleton/config.yaml (llm.temperature), kept near 0.
  * A structured-output helper: call the model, parse JSON, validate against a
    JSON schema (jsonschema if installed, else a light manual check).

Stdlib only for the hard dependency path. `yaml` is used to read config but has a
JSON fallback; `jsonschema` is optional (light manual validation if absent).
"""

from __future__ import annotations

import hashlib
import re
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------- #
# Paths — everything this module writes lives under llm/data/ (per protocol).
# --------------------------------------------------------------------------- #
_MODULE_DIR = Path(__file__).resolve().parent
_DATA_DIR = _MODULE_DIR / "data"
_CACHE_DIR = _DATA_DIR / "cache"
_USAGE_LOG = _DATA_DIR / "usage.jsonl"
_REPO_ROOT = _MODULE_DIR.parent
_CONFIG_PATH = _REPO_ROOT / "skeleton" / "config.yaml"


class LLMError(RuntimeError):
    """Any client-level failure (backend exhausted retries, bad structured output)."""


# --------------------------------------------------------------------------- #
# Config loading — read llm.* from skeleton/config.yaml. Never hardcode values.
# --------------------------------------------------------------------------- #
def load_llm_config(path: str | Path = _CONFIG_PATH) -> dict[str, Any]:
    """Read the `llm:` block from config. Tolerant: returns {} if absent/unreadable."""
    path = Path(path)
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        cfg = yaml.safe_load(text) or {}
    except Exception:
        cfg = _min_yaml_llm_block(text)
    return (cfg.get("llm") or {}) if isinstance(cfg, dict) else {}


def load_skill_aliases(path: str | Path = _CONFIG_PATH) -> dict[str, list[str]]:
    """Read the `skill_aliases:` block. Used by normalise_skill (rule-first)."""
    path = Path(path)
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        cfg = yaml.safe_load(text) or {}
        aliases = cfg.get("skill_aliases") or {}
    except Exception:
        aliases = {}
    return aliases if isinstance(aliases, dict) else {}


def _min_yaml_llm_block(text: str) -> dict[str, Any]:
    """Ultra-light fallback parser for just the `llm:` block if PyYAML is missing.

    Only handles the flat scalar keys we need (model/temperature/cache/max_retries).
    """
    out: dict[str, Any] = {"llm": {}}
    in_llm = False
    for raw in text.splitlines():
        if raw.strip().startswith("#") or not raw.strip():
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            in_llm = raw.strip() == "llm:"
            continue
        if in_llm and raw.startswith("  ") and ":" in raw:
            k, _, v = raw.strip().partition(":")
            v = v.split("#", 1)[0].strip().strip('"').strip("'")
            if v.lower() in ("true", "false"):
                val: Any = v.lower() == "true"
            else:
                try:
                    val = int(v)
                except ValueError:
                    try:
                        val = float(v)
                    except ValueError:
                        val = v
            out["llm"][k.strip()] = val
    return out


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
@dataclass
class LLMResponse:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class Backend:
    """A backend turns (system, user, temperature) into an LLMResponse."""

    name: str = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        raise NotImplementedError


class MockBackend(Backend):
    """Deterministic, OFFLINE backend. No API key, no network.

    It routes on a marker embedded in the system prompt (``[[task:<name>]]``)
    so capabilities get stable, schema-shaped answers without a real model.
    Every response is a pure function of the inputs → reproducible tests.

    A `call_count` lets tests prove that a cache HIT never reaches the backend.
    Extra handlers can be registered for tasks not built in.
    """

    name = "mock"

    def __init__(self) -> None:
        self.call_count = 0
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}

    def register(self, task: str, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._handlers[task] = handler

    def available(self) -> bool:  # always — that's the point
        return True

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        self.call_count += 1
        task = _extract_task_marker(system)
        try:
            payload = json.loads(user) if user.strip().startswith("{") else {"_raw": user}
        except json.JSONDecodeError:
            payload = {"_raw": user}
        handler = self._handlers.get(task, _MOCK_HANDLERS.get(task, _mock_default))
        result = handler(payload)
        text = json.dumps(result, ensure_ascii=False)
        return LLMResponse(
            text=text,
            prompt_tokens=_approx_tokens(system) + _approx_tokens(user),
            completion_tokens=_approx_tokens(text),
            model="mock-deterministic",
        )


class StubBackend(Backend):
    """Real-provider SHAPE. Reads an API key from env; NOT wired to a provider.

    This exists so swapping in a real model is a one-function change and the
    client's retry/cache/log paths are exercised against the real interface.
    It intentionally raises until someone wires an actual SDK call.
    """

    name = "stub"

    def __init__(self, api_key_env: str = "LLM_API_KEY", model: str = "REPLACE_ME") -> None:
        self.api_key_env = api_key_env
        self.model = model

    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env))

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise LLMError(
                f"StubBackend: no API key in ${self.api_key_env}. "
                "Set it, or use MockBackend for offline/deterministic runs."
            )
        # TODO wire provider: instantiate the real SDK client here, e.g.
        #   from anthropic import Anthropic
        #   resp = Anthropic(api_key=api_key).messages.create(
        #       model=self.model, temperature=temperature,
        #       system=system, messages=[{"role": "user", "content": user}],
        #       max_tokens=1024)
        #   return LLMResponse(text=resp.content[0].text,
        #                      prompt_tokens=resp.usage.input_tokens,
        #                      completion_tokens=resp.usage.output_tokens,
        #                      model=self.model)
        raise LLMError(
            "StubBackend is not wired to a provider yet (# TODO wire provider). "
            "This is expected offline; the pipeline runs on MockBackend."
        )


# --------------------------------------------------------------------------- #
# ClaudeCliBackend — transport over the user's logged-in `claude` CLI.
# --------------------------------------------------------------------------- #
class ClaudeCliBackend(Backend):
    """Shell out to the locally-installed `claude` CLI (Claude Code, headless).

    This is a pure TRANSPORT: it turns (system, user, temperature) into text by
    invoking `claude -p --output-format json --model <model>` with the prompt on
    STDIN. All the client-level features (cache, usage log, retries) live in
    LLMClient which wraps this — the backend just moves bytes.

    Requirements:
      * `claude` must be on PATH (resolved via shutil.which) or at the fallback
        /usr/local/bin/claude, and
      * it must be LOGGED IN on the machine that runs this (`claude login`).

    The not-logged-in case is detected and turned into a clear LLMError so the
    caller isn't left guessing why an empty/blocked call came back.
    """

    name = "claude_cli"

    _FALLBACK_BIN = "/usr/local/bin/claude"

    def __init__(self, model: str = "sonnet", cli_timeout_seconds: float = 120.0) -> None:
        self.model = model
        self.cli_timeout_seconds = float(cli_timeout_seconds)

    @staticmethod
    def resolve_binary() -> Optional[str]:
        """Locate the `claude` executable: PATH first, then the known fallback."""
        found = shutil.which("claude")
        if found:
            return found
        if Path(ClaudeCliBackend._FALLBACK_BIN).exists():
            return ClaudeCliBackend._FALLBACK_BIN
        return None

    def available(self) -> bool:
        return self.resolve_binary() is not None

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        claude = self.resolve_binary()
        if claude is None:
            raise LLMError(
                "claude CLI not found on PATH or at /usr/local/bin/claude. "
                "Install Claude Code, or use MockBackend for offline runs."
            )

        # We fold system + user into a single prompt on STDIN. Passing the prompt
        # via STDIN (not as a positional arg) avoids the CLI's arg/stdin warning
        # and keeps large prompts off the argv length limit.
        prompt = f"{system}\n\n{user}" if system else user

        try:
            proc = subprocess.run(
                [claude, "-p", "--output-format", "json", "--model", self.model],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.cli_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            # Transient by nature — let the client's retry loop have a go.
            raise TimeoutError(
                f"claude CLI timed out after {self.cli_timeout_seconds}s"
            ) from exc
        except OSError as exc:
            raise LLMError(f"failed to launch claude CLI ({claude}): {exc}") from exc

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # Not-logged-in is a hard, non-transient failure — surface it clearly.
        blob = f"{stdout}\n{stderr}"
        if "Not logged in" in blob or "Please run /login" in blob:
            raise LLMError(
                "claude CLI not logged in — run `claude login` (or `/login`) "
                "on the machine that runs this."
            )

        if proc.returncode != 0:
            # Non-zero without a recognised auth message: treat as transient so
            # retries apply, but carry the stderr for diagnosis.
            raise RuntimeError(
                f"claude CLI exited {proc.returncode}: {stderr.strip() or stdout.strip()}"
            )

        text, resp_model = self._parse_stdout(stdout)
        if not text.strip():
            # Empty result with rc=0 — transient (usage limit, blocked turn, …).
            # Raise RuntimeError so the client's retry loop has a go, and carry
            # whatever the CLI said so the failure is diagnosable.
            raise RuntimeError(
                "claude CLI returned an empty result "
                f"(stderr: {stderr.strip()[:200] or 'none'}; "
                f"stdout head: {stdout.strip()[:200] or 'empty'})"
            )
        return LLMResponse(
            text=text,
            prompt_tokens=_approx_tokens(prompt),
            completion_tokens=_approx_tokens(text),
            model=resp_model or self.model,
        )

    @staticmethod
    def _parse_stdout(stdout: str) -> tuple[str, str]:
        """Parse Claude Code's JSON envelope → (result_text, model).

        Shape: {"type":"result","subtype":"success","result":"<text>", ...}.
        If stdout isn't JSON (or lacks `result`), return the raw stdout as text.
        An explicit error envelope raises RuntimeError (transient → retried).
        """
        raw = stdout.strip()
        if not raw:
            return "", ""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return raw, ""
        if isinstance(data, dict) and "result" in data:
            if data.get("is_error") or str(data.get("subtype", "success")) != "success":
                raise RuntimeError(
                    f"claude CLI reported an error envelope "
                    f"(subtype={data.get('subtype')!r}): {str(data.get('result'))[:300]}"
                )
            result = data.get("result")
            model = str(data.get("model") or "")
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            return text, model
        # Valid JSON but not the result envelope — hand back the raw text.
        return raw, ""


class CodexCliBackend(Backend):
    """Shell out to the locally-installed `codex` CLI (OpenAI Codex, headless).

    Pure TRANSPORT, mirror of ClaudeCliBackend: invokes
        codex exec --skip-git-repo-check -s read-only \
              --output-last-message <tmpfile> [-m <model>] -
    with the prompt on STDIN and reads the agent's final message from the
    tmpfile (avoids parsing the JSONL event stream). Sandbox is read-only —
    codex is used purely as a text engine here, never as a file-editing agent.

    Requirements: `codex` on PATH (or /usr/local/bin/codex) and logged in on
    this machine (`codex login` — a ChatGPT account login).
    """

    name = "codex_cli"

    _FALLBACK_BIN = "/usr/local/bin/codex"

    def __init__(self, model: str = "", cli_timeout_seconds: float = 120.0) -> None:
        self.model = model              # "" → let the codex CLI use its default
        self.cli_timeout_seconds = float(cli_timeout_seconds)

    @staticmethod
    def resolve_binary() -> Optional[str]:
        found = shutil.which("codex")
        if found:
            return found
        if Path(CodexCliBackend._FALLBACK_BIN).exists():
            return CodexCliBackend._FALLBACK_BIN
        return None

    def available(self) -> bool:
        return self.resolve_binary() is not None

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        import tempfile

        codex = self.resolve_binary()
        if codex is None:
            raise LLMError(
                "codex CLI not found on PATH or at /usr/local/bin/codex. "
                "Install it (`npm install -g @openai/codex` or `brew install codex`), "
                "or set llm.backend to another backend."
            )

        prompt = f"{system}\n\n{user}" if system else user

        with tempfile.NamedTemporaryFile("r", suffix=".txt", delete=False) as tf:
            out_path = Path(tf.name)
        try:
            cmd = [codex, "exec", "--skip-git-repo-check", "-s", "read-only",
                   "--output-last-message", str(out_path)]
            if self.model:
                cmd += ["-m", self.model]
            cmd += ["-"]   # read the prompt from stdin
            try:
                proc = subprocess.run(
                    cmd, input=prompt, capture_output=True, text=True,
                    timeout=self.cli_timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(
                    f"codex CLI timed out after {self.cli_timeout_seconds}s"
                ) from exc
            except OSError as exc:
                raise LLMError(f"failed to launch codex CLI ({codex}): {exc}") from exc

            blob = f"{proc.stdout or ''}\n{proc.stderr or ''}"
            low = blob.lower()
            if ("login" in low and ("not logged in" in low or "codex login" in low
                                    or "please log in" in low or "need to log in" in low)):
                raise LLMError(
                    "codex CLI not logged in — run `codex login` on this machine "
                    "(uses your ChatGPT account)."
                )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"codex CLI exited {proc.returncode}: "
                    f"{(proc.stderr or proc.stdout or '').strip()[:300]}"
                )

            text = ""
            if out_path.exists():
                text = out_path.read_text(encoding="utf-8").strip()
            if not text:
                # Some codex builds print the final message to stdout instead.
                text = (proc.stdout or "").strip()
            if not text:
                raise RuntimeError(
                    "codex CLI returned an empty result "
                    f"(stderr: {(proc.stderr or '').strip()[:200] or 'none'})"
                )
            return LLMResponse(
                text=text,
                prompt_tokens=_approx_tokens(prompt),
                completion_tokens=_approx_tokens(text),
                model=self.model or "codex-default",
            )
        finally:
            try:
                out_path.unlink()
            except FileNotFoundError:
                pass


# --------------------------------------------------------------------------- #
# Backend selector — pick a backend by name (config `llm.backend`).
# --------------------------------------------------------------------------- #
def make_backend(cfg: dict[str, Any]) -> Backend:
    """Build the backend named by `cfg['backend']`.

      claude_cli -> ClaudeCliBackend (model + cli_timeout_seconds from config)
      codex_cli  -> CodexCliBackend  (codex_model + cli_timeout_seconds from config)
      mock       -> MockBackend       (offline, deterministic)
      stub       -> StubBackend       (real-provider shape; unwired)

    Defaults to MockBackend for any unknown/absent value so nothing goes live by
    accident. This is only consulted when no explicit backend is passed in.
    """
    name = str((cfg or {}).get("backend", "mock") or "mock").strip().lower()
    if name == "claude_cli":
        return ClaudeCliBackend(
            model=str(cfg.get("model", "sonnet") or "sonnet"),
            cli_timeout_seconds=float(cfg.get("cli_timeout_seconds", 120) or 120),
        )
    if name == "codex_cli":
        return CodexCliBackend(
            model=str(cfg.get("codex_model", "") or ""),   # "" = codex CLI default
            cli_timeout_seconds=float(cfg.get("cli_timeout_seconds", 120) or 120),
        )
    if name == "stub":
        return StubBackend(model=str(cfg.get("model", "REPLACE_ME") or "REPLACE_ME"))
    return MockBackend()


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #
@dataclass
class LLMClient:
    """Model-agnostic client: retries · cache · usage log · structured output.

    Cache and log dirs default under llm/data/. Pass a MockBackend for offline
    determinism, or a StubBackend (env key) for the real thing once wired.
    """

    backend: Backend = field(default_factory=MockBackend)
    model: str = "REPLACE_ME"
    temperature: float = 0.0
    max_retries: int = 3
    cache_enabled: bool = True
    cache_dir: Path = _CACHE_DIR
    usage_log: Path = _USAGE_LOG
    price_per_1k_prompt: float = 0.0      # cost knobs; 0 for mock/unpriced runs
    price_per_1k_completion: float = 0.0
    _backoff_base: float = 0.2            # seconds; overridable so tests stay fast

    def __post_init__(self) -> None:
        self.cache_dir = Path(self.cache_dir)
        self.usage_log = Path(self.usage_log)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.usage_log.parent.mkdir(parents=True, exist_ok=True)

    # -- factory: build from skeleton/config.yaml --------------------------- #
    @classmethod
    def from_config(
        cls,
        backend: Optional[Backend] = None,
        config_path: str | Path = _CONFIG_PATH,
        **overrides: Any,
    ) -> "LLMClient":
        cfg = load_llm_config(config_path)
        kwargs: dict[str, Any] = dict(
            backend=backend if backend is not None else make_backend(cfg),
            model=cfg.get("model", "REPLACE_ME"),
            temperature=float(cfg.get("temperature", 0.0) or 0.0),
            max_retries=int(cfg.get("max_retries", 3) or 3),
            cache_enabled=bool(cfg.get("cache", True)),
        )
        kwargs.update(overrides)
        return cls(**kwargs)

    # -- cache key ---------------------------------------------------------- #
    @staticmethod
    def cache_key(system: str, user: str, temperature: float, model: str,
                  backend: str = "") -> str:
        """sha256 over prompt + input (+ every knob that changes the answer).

        `backend` IS part of the key: a MockBackend answer and a claude_cli
        answer to the same prompt are different artefacts, and must never
        satisfy each other's cache lookups. (Bug caught 2026-07-14: mock rows
        cached during an offline run were served to the live backend.)
        """
        h = hashlib.sha256()
        h.update(system.encode("utf-8"))
        h.update(b"\x00")
        h.update(user.encode("utf-8"))
        h.update(f"\x00{temperature}\x00{model}\x00{backend}".encode("utf-8"))
        return h.hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def _cache_get(self, key: str) -> Optional[LLMResponse]:
        if not self.cache_enabled:
            return None
        p = self._cache_path(key)
        if not p.exists():
            return None
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return LLMResponse(**d)
        except Exception:
            return None

    def _cache_put(self, key: str, resp: LLMResponse) -> None:
        if not self.cache_enabled:
            return
        p = self._cache_path(key)
        p.write_text(
            json.dumps(
                {
                    "text": resp.text,
                    "prompt_tokens": resp.prompt_tokens,
                    "completion_tokens": resp.completion_tokens,
                    "model": resp.model,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    # -- usage / cost log --------------------------------------------------- #
    def _log_usage(self, task: str, resp: LLMResponse, cache_hit: bool) -> None:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "task": task,
            "backend": self.backend.name,
            "model": resp.model or self.model,
            "cache_hit": cache_hit,
            "prompt_tokens": resp.prompt_tokens,
            "completion_tokens": resp.completion_tokens,
            "total_tokens": resp.total_tokens,
            "cost_usd": round(self._cost(resp), 6),
        }
        with self.usage_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _cost(self, resp: LLMResponse) -> float:
        return (
            resp.prompt_tokens / 1000.0 * self.price_per_1k_prompt
            + resp.completion_tokens / 1000.0 * self.price_per_1k_completion
        )

    # -- core call ---------------------------------------------------------- #
    def complete(self, system: str, user: str, *, task: str = "generic") -> LLMResponse:
        """One completion, with cache → (retry/backoff) → log. Cache HIT skips backend."""
        key = self.cache_key(system, user, self.temperature, self.model,
                             backend=self.backend.name)
        cached = self._cache_get(key)
        if cached is not None:
            self._log_usage(task, cached, cache_hit=True)
            return cached

        resp = self._call_with_retries(system, user)
        self._cache_put(key, resp)
        self._log_usage(task, resp, cache_hit=False)
        return resp

    def _call_with_retries(self, system: str, user: str) -> LLMResponse:
        last: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return self.backend.complete(system, user, self.temperature)
            except LLMError:
                raise  # non-transient by contract (e.g. stub not wired) — don't spin
            except Exception as exc:  # transient: network/rate-limit/etc.
                last = exc
                if attempt < self.max_retries:
                    time.sleep(self._backoff_base * (2 ** (attempt - 1)))
        raise LLMError(f"backend failed after {self.max_retries} attempts: {last}")

    # -- structured output helper ------------------------------------------ #
    def complete_json(
        self,
        system: str,
        user: str,
        *,
        schema: Optional[dict[str, Any]] = None,
        task: str = "generic",
        json_attempts: int = 2,
    ) -> dict[str, Any]:
        data, _response = self.complete_json_with_response(
            system,
            user,
            schema=schema,
            task=task,
            json_attempts=json_attempts,
        )
        return data

    def complete_json_with_response(
        self,
        system: str,
        user: str,
        *,
        schema: Optional[dict[str, Any]] = None,
        task: str = "generic",
        json_attempts: int = 2,
    ) -> tuple[dict[str, Any], LLMResponse]:
        """Complete, parse JSON (leniently), validate against `schema`.

        The schema is included in the model request, not merely applied after
        the response.  On a failed attempt the validation error is fed back on
        the retry so a real backend can repair field names or types.

        Lenient parse tolerates markdown fences and prose around the object
        (real models do this despite instructions). On a bad response the cache
        entry is EVICTED before retrying, so a poisoned answer can never satisfy
        this or any future lookup. Raises LLMError with a response preview on
        final failure."""
        schema_contract = ""
        if schema is not None:
            schema_contract = (
                "\n\nREQUIRED OUTPUT CONTRACT (JSON Schema):\n"
                + json.dumps(schema, ensure_ascii=False, sort_keys=True)
                + "\nReturn one JSON object satisfying this contract exactly. "
                  "Do not rename keys or add properties."
            )

        last_err = ""
        preview = ""
        for attempt in range(1, json_attempts + 1):
            attempt_system = system + schema_contract
            if attempt > 1 and last_err:
                attempt_system += (
                    "\n\nYour previous response failed validation: "
                    + last_err
                    + "\nCorrect that error and return the complete JSON object only."
                )
            resp = self.complete(attempt_system, user, task=task)
            try:
                data = _coerce_json(resp.text)
                if schema is not None:
                    validate_json(data, schema)
                if not isinstance(data, dict):
                    raise LLMError("structured output root must be an object")
                return data, resp
            except (json.JSONDecodeError, LLMError) as exc:
                last_err = str(exc)
                preview = repr((resp.text or "")[:200])
                self._evict(attempt_system, user)  # never retain a poisoned answer
        raise LLMError(
            f"structured output failed for task '{task}' after {json_attempts} "
            f"attempts: {last_err}; last response preview: {preview}"
        )

    def _evict(self, system: str, user: str) -> None:
        """Remove a cached response so the next call re-hits the backend."""
        key = self.cache_key(system, user, self.temperature, self.model,
                             backend=self.backend.name)
        try:
            self._cache_path(key).unlink()
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------- #
# Lenient JSON coercion — real models fence/pad JSON despite instructions
# --------------------------------------------------------------------------- #
def _coerce_json(text: str) -> Any:
    """Parse model output into JSON, tolerating ```json fences and prose around
    the object. Raises json.JSONDecodeError if nothing parseable is found."""
    t = (text or "").strip()
    if t:
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            pass
        m = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except json.JSONDecodeError:
                pass
        for open_ch, close_ch in (("{", "}"), ("[", "]")):
            start = t.find(open_ch)
            if start == -1:
                continue
            depth, in_str, esc = 0, False, False
            for i in range(start, len(t)):
                c = t[i]
                if in_str:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == '"':
                        in_str = False
                elif c == '"':
                    in_str = True
                elif c == open_ch:
                    depth += 1
                elif c == close_ch:
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(t[start:i + 1])
                        except json.JSONDecodeError:
                            break
    raise json.JSONDecodeError("no parseable JSON found in model output", t or " ", 0)


# --------------------------------------------------------------------------- #
# JSON-schema validation (jsonschema if present, else a light manual check)
# --------------------------------------------------------------------------- #
def validate_json(data: Any, schema: dict[str, Any]) -> None:
    """Validate `data` against `schema`. Uses jsonschema if importable; else manual.

    Raises LLMError with a readable message on any violation.
    """
    try:
        import jsonschema  # type: ignore

        try:
            jsonschema.validate(instance=data, schema=schema)
            return
        except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
            raise LLMError(f"schema validation failed: {exc.message}")
    except ModuleNotFoundError:
        _manual_validate(data, schema, path="$")


def _manual_validate(data: Any, schema: dict[str, Any], path: str) -> None:
    """A deliberately small validator: type, required, properties, enum, items."""
    t = schema.get("type")
    if t == "object":
        if not isinstance(data, dict):
            raise LLMError(f"{path}: expected object, got {type(data).__name__}")
        for req in schema.get("required", []):
            if req not in data:
                raise LLMError(f"{path}: missing required property '{req}'")
        props = schema.get("properties", {})
        for k, sub in props.items():
            if k in data:
                _manual_validate(data[k], sub, f"{path}.{k}")
    elif t == "array":
        if not isinstance(data, list):
            raise LLMError(f"{path}: expected array, got {type(data).__name__}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(data):
                _manual_validate(item, item_schema, f"{path}[{i}]")
    elif t == "string":
        if not isinstance(data, str):
            raise LLMError(f"{path}: expected string, got {type(data).__name__}")
    elif t == "integer":
        if not isinstance(data, int) or isinstance(data, bool):
            raise LLMError(f"{path}: expected integer, got {type(data).__name__}")
    elif t == "number":
        if isinstance(data, bool) or not isinstance(data, (int, float)):
            raise LLMError(f"{path}: expected number, got {type(data).__name__}")
    elif t == "boolean":
        if not isinstance(data, bool):
            raise LLMError(f"{path}: expected boolean, got {type(data).__name__}")
    # null / missing type: accept.

    if "enum" in schema and data not in schema["enum"]:
        raise LLMError(f"{path}: {data!r} not in enum {schema['enum']}")

    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            raise LLMError(f"{path}: {data} < minimum {schema['minimum']}")
        if "maximum" in schema and data > schema["maximum"]:
            raise LLMError(f"{path}: {data} > maximum {schema['maximum']}")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _approx_tokens(s: str) -> int:
    """Rough token estimate for cost logging (≈4 chars/token). No tokenizer dep."""
    return max(1, len(s) // 4)


_TASK_MARK_OPEN = "[[task:"
_TASK_MARK_CLOSE = "]]"


def task_marker(task: str) -> str:
    """The marker a prompt embeds so MockBackend can route deterministically."""
    return f"{_TASK_MARK_OPEN}{task}{_TASK_MARK_CLOSE}"


def _extract_task_marker(system: str) -> str:
    i = system.find(_TASK_MARK_OPEN)
    if i == -1:
        return "generic"
    j = system.find(_TASK_MARK_CLOSE, i)
    if j == -1:
        return "generic"
    return system[i + len(_TASK_MARK_OPEN) : j]


# --------------------------------------------------------------------------- #
# Deterministic mock handlers (offline stand-ins for the real model)
# --------------------------------------------------------------------------- #
def _mock_default(payload: dict[str, Any]) -> dict[str, Any]:
    return {"echo": payload}


# The real handlers live in capabilities-adjacent logic but are registered here
# so MockBackend is self-contained. capabilities.py fills these in at import.
_MOCK_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}


def register_mock_handler(task: str, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
    """Let capabilities.py contribute deterministic mock behaviour for a task."""
    _MOCK_HANDLERS[task] = handler
