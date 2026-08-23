"""Minimal capability-scoped interface to an external general orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class WorkRequest:
    request_id: str
    task_kind: str
    input_sha256: str
    idempotency_key: str
    required_capabilities: tuple[str, ...]
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class WorkReceipt:
    request_id: str
    status: str
    output_sha256: str | None
    evidence_uri: str | None
    completed_at: str | None


class OrchestratorAdapter(Protocol):
    def submit(self, request: WorkRequest) -> WorkReceipt: ...

    def inspect(self, request_id: str) -> WorkReceipt: ...

    def cancel(self, request_id: str) -> WorkReceipt: ...
