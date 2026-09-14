"""Standard-library client for the complete Scrapling sidecar runtime."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from market_aligner.applications.canonical import ContractValidationError
from market_aligner.collectors.evidence import (
    sanitized_fetch_engine,
    sanitized_transport_receipt,
    sanitized_worker_response,
)


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

    def __init__(
        self,
        root: Path,
        config: Mapping[str, Any] | None = None,
        *,
        protected_roots: tuple[str | Path, ...] = (),
    ) -> None:
        self.root = Path(root).resolve()
        self.config = dict(config or {})
        self.protected_roots = tuple(
            dict.fromkeys((self.root, *(Path(value).resolve() for value in protected_roots)))
        )
        configured = self.config.get("runtime_python", ".venv-scrapling/bin/python")
        runtime = Path(str(configured))
        self.runtime = runtime if runtime.is_absolute() else self.root / runtime
        self.worker_module = str(self.config.get("worker_module", "market_aligner.collectors.scrapling_worker"))
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
        environment = os.environ.copy()
        package_root = str(Path(__file__).resolve().parents[2])
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (package_root, environment.get("PYTHONPATH", "")) if part
        )
        completed = subprocess.run(
            [str(self.runtime), "-m", self.worker_module],
            cwd=self.root,
            env=environment,
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
            raise ScraplingError(
                f"Scrapling worker returned no protocol result (exit {completed.returncode})"
            )
        if not payload.get("ok"):
            raise ScraplingError("Scrapling worker failed")
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
        try:
            return sanitized_worker_response(result, protected_roots=self.protected_roots)
        except ContractValidationError as exc:
            raise ScraplingError("invalid fetch response") from exc

    def fetch_with_chain(self, url: str) -> ScraplingResult:
        chain = list(self.config.get("fallback_chain") or ())
        if not chain:
            chain = [
                {"engine": "static", "method": "get", "kwargs": {}},
                {"engine": "dynamic", "kwargs": {}},
            ]
        attempts: list[dict[str, Any]] = []
        minimum = int(self.config.get("minimum_body_bytes", 128))
        accepted_statuses = tuple(int(code) for code in self.config.get("accepted_statuses", range(200, 400)))
        for stage in chain:
            try:
                engine = sanitized_fetch_engine(stage.get("engine"))
            except ContractValidationError as exc:
                raise ScraplingError("invalid fallback engine configuration") from exc
            request = {
                "operation": "fetch",
                "engine": engine,
                "url": url,
                "method": str(stage.get("method", "get")),
                "kwargs": dict(stage.get("kwargs") or {}),
            }
            try:
                raw_response = self.execute(
                    request, timeout=float(stage.get("timeout_seconds", self.timeout))
                )
                response = sanitized_worker_response(
                    raw_response, protected_roots=self.protected_roots
                )
                attempt = {
                    **sanitized_transport_receipt(response, engine=engine),
                    "ok": True,
                }
                attempts.append(attempt)
                if int(response.get("status", 0)) in accepted_statuses and int(response.get("body_bytes", 0)) >= minimum:
                    return ScraplingResult(engine, response, tuple(attempts))
            except ContractValidationError:
                attempts.append(
                    {"engine": engine, "ok": False, "error_code": "invalid_worker_response"}
                )
            except ScraplingError:
                attempts.append({"engine": engine, "ok": False, "error_code": "worker_error"})
            except subprocess.TimeoutExpired:
                attempts.append({"engine": engine, "ok": False, "error_code": "worker_timeout"})
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
