"""Standard-library client for the complete Scrapling sidecar runtime."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


RESULT_PREFIX = "__SCRAPLING_RESULT__="


class ScraplingError(RuntimeError):
    """The sidecar could not execute a request."""


class ScraplingFetchError(ScraplingError):
    def __init__(self, message: str, attempts: Sequence[Mapping[str, Any]]) -> None:
        super().__init__(message)
        self.attempts = tuple(dict(row) for row in attempts)


@dataclass(frozen=True)
class ScraplingResult:
    engine: str
    response: dict[str, Any]
    attempts: tuple[dict[str, Any], ...]


class ScraplingClient:
    """Invoke pinned Scrapling without importing it into the main Python 3.14 app."""

    def __init__(self, root: Path, config: Mapping[str, Any] | None = None) -> None:
        self.root = Path(root).resolve()
        self.config = dict(config or {})
        if "runtime_python" in self.config:
            configured = self.config["runtime_python"]
        elif runtime_directory := os.environ.get("AGENTIC_SCRAPLING_RUNTIME_DIR"):
            configured = Path(runtime_directory) / "bin" / "python"
        else:
            configured = ".venv-scrapling/bin/python"
        runtime = Path(str(configured))
        self.runtime = runtime if runtime.is_absolute() else self.root / runtime
        self.worker_module = str(self.config.get("worker_module", "scraper.scrapling_worker"))
        self.timeout = float(self.config.get("command_timeout_seconds", 240))

    @property
    def available(self) -> bool:
        return self.runtime.is_file()

    def execute(self, request: Mapping[str, Any], *, timeout: float | None = None) -> Any:
        if not self.available:
            raise ScraplingError(
                f"full Scrapling runtime is missing at {self.runtime}; "
                "run scripts/install_scrapling_full.sh"
            )
        completed = subprocess.run(
            [str(self.runtime), "-m", self.worker_module],
            cwd=self.root,
            input=json.dumps(dict(request), ensure_ascii=False),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout or self.timeout,
            check=False,
        )
        payload: dict[str, Any] | None = None
        for line in reversed(completed.stdout.splitlines()):
            if line.startswith(RESULT_PREFIX):
                payload = json.loads(line[len(RESULT_PREFIX):])
                break
        if payload is None:
            detail = (completed.stderr or completed.stdout).strip()[-4000:]
            raise ScraplingError(
                f"Scrapling worker returned no protocol result (exit {completed.returncode}): {detail}"
            )
        if not payload.get("ok"):
            detail = str(payload.get("message") or payload.get("error") or "unknown error")
            logs = completed.stderr.strip()[-2000:]
            if logs:
                detail = f"{detail}; worker logs: {logs}"
            raise ScraplingError(detail)
        return payload.get("result")

    def capabilities(self) -> dict[str, Any]:
        result = self.execute({"operation": "capabilities"})
        if not isinstance(result, dict):
            raise ScraplingError("invalid capabilities response")
        return result

    def fetch(self, engine: str, url: str, **kwargs: Any) -> dict[str, Any]:
        result = self.execute({
            "operation": "fetch",
            "engine": engine,
            "url": url,
            "method": kwargs.pop("method", "get"),
            "kwargs": kwargs,
        })
        if not isinstance(result, dict):
            raise ScraplingError("invalid fetch response")
        return result

    def fetch_with_chain(self, url: str) -> ScraplingResult:
        chain = list(self.config.get("fallback_chain") or ())
        if not chain:
            chain = [
                {"engine": "static", "method": "get", "kwargs": {}},
                {"engine": "dynamic", "kwargs": {}},
                {"engine": "stealth", "kwargs": {"solve_cloudflare": True}},
            ]
        attempts: list[dict[str, Any]] = []
        minimum = int(self.config.get("minimum_body_bytes", 128))
        accepted_statuses = tuple(int(code) for code in self.config.get("accepted_statuses", range(200, 400)))
        for stage in chain:
            engine = str(stage["engine"])
            request = {
                "operation": "fetch",
                "engine": engine,
                "url": url,
                "method": str(stage.get("method", "get")),
                "kwargs": dict(stage.get("kwargs") or {}),
            }
            try:
                response = self.execute(request, timeout=float(stage.get("timeout_seconds", self.timeout)))
                attempt = {"engine": engine, "ok": True, "response": response}
                attempts.append(attempt)
                if int(response.get("status", 0)) in accepted_statuses and int(response.get("body_bytes", 0)) >= minimum:
                    return ScraplingResult(engine, response, tuple(attempts))
            except (ScraplingError, subprocess.TimeoutExpired) as exc:
                attempts.append({
                    "engine": engine,
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                })
        raise ScraplingFetchError("all configured Scrapling engines were exhausted", attempts)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    client = ScraplingClient(root)
    request = json.load(sys.stdin)
    json.dump(client.execute(request), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
