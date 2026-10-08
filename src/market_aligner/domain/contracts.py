"""Versioned deterministic seams shared by collectors and assessment."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, TypeVar


CONTRACT_VERSION = "1.0.0"
T = TypeVar("T")


@dataclass(frozen=True)
class JobUrl:
    board: str
    job_id: str
    url: str
    posted_at: str | None = None
    discovered_at: str | None = None
    market: str | None = None

    @property
    def key(self) -> str:
        return f"{self.board}:{self.job_id}"


@dataclass(frozen=True)
class RawPosting:
    board: str
    job_id: str
    url: str
    fetched_at: str
    raw_text: str | None = None
    raw_json: dict[str, Any] | None = None
    content_type: str | None = None
    http_status: int | None = None
    content_sha256: str | None = None
    public_content_base64: str | None = None

    @property
    def key(self) -> str:
        return f"{self.board}:{self.job_id}"


@dataclass(frozen=True)
class Vacancy:
    board: str
    job_id: str
    url: str
    title: str = ""
    company: str = ""
    location: str = ""
    description: str = ""
    responsibilities: tuple[str, ...] = ()
    required_skills: tuple[str, ...] = ()
    preferred_skills: tuple[str, ...] = ()
    required_qualifications: tuple[str, ...] = ()
    preferred_qualifications: tuple[str, ...] = ()
    work_authorisation: tuple[str, ...] = ()
    salary_text: str = ""
    contract_type: str = ""
    remote_policy: str = "unknown"
    seniority: str = "unknown"
    posted_at: str | None = None
    expires_at: str | None = None
    extraction_confidence: float | None = None
    extraction_receipt_id: str | None = None
    source_content_sha256: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.board}:{self.job_id}"


def to_dict(value: Any) -> dict[str, Any]:
    return dataclasses.asdict(value)


def from_dict(cls: type[T], data: dict[str, Any]) -> T:
    known = {item.name for item in dataclasses.fields(cls)}
    return cls(**{key: value for key, value in data.items() if key in known})


def write_jsonl(path: str | Path, rows: Iterable[Any]) -> int:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with destination.open("w", encoding="utf-8") as handle:
        for row in rows:
            payload = row if isinstance(row, dict) else to_dict(row)
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def read_jsonl(path: str | Path, cls: type[T] | None = None) -> Iterator[T | dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                payload = json.loads(line)
                yield from_dict(cls, payload) if cls else payload
