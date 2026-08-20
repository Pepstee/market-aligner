"""In-process service API shared by CLI and future local transports."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from market_aligner.applications.handoff import HandoffEnvelope
from market_aligner.applications.producer import produce_handoff
from market_aligner.assessment.opportunity import OpportunityDecision, apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, ScoreResult, ScoringParams, score
from market_aligner.collectors.engine import Collector
from market_aligner.config import ProductPaths
from market_aligner.config_loader import load_config
from market_aligner.profiler.store import ProfileStore
from market_aligner.research.store import AssessmentStore


@dataclass(frozen=True)
class AssessmentRequest:
    profile_id: str
    job_key: str
    track: str
    url: str
    title: str
    company: str
    extraction_confidence: float
    axes: AssessmentAxes


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _relative_data_path(value: object, label: str) -> str:
    path = Path(str(value))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"{label} must stay below the external data home")
    return str(path)


def _validate_collection_config(config: dict[str, Any]) -> None:
    boards = (config.get("boards") or {}).get("enabled") or []
    if not isinstance(boards, list) or not boards or any(
        not isinstance(board, str) or not board.strip() for board in boards
    ):
        raise ValueError("collection config requires non-empty boards.enabled")
    if len(boards) != len(set(boards)):
        raise ValueError("collection config boards.enabled must be unique")
    terms = config.get("search_terms") or []
    if not isinstance(terms, list) or any(not isinstance(term, str) for term in terms):
        raise ValueError("collection config search_terms must be a string array")
    io = config.get("io") or {}
    if not isinstance(io, dict):
        raise ValueError("collection config io must be an object")
    for key in ("database", "job_urls", "raw_cache"):
        if key in io:
            _relative_data_path(io[key], f"io.{key}")
    for index, root in enumerate(io.get("raw_cache_roots") or []):
        _relative_data_path(root, f"io.raw_cache_roots[{index}]")
    scrapling = config.get("scrapling") or {}
    if not isinstance(scrapling, dict):
        raise ValueError("collection config scrapling must be an object")
    if "runtime_root" in scrapling:
        _relative_data_path(scrapling["runtime_root"], "scrapling.runtime_root")


def _write_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical_bytes(receipt))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


class CollectionService:
    """Bounded orchestration around the existing resumable Collector."""

    def __init__(
        self,
        data_home: str | Path | None = None,
        *,
        collector_factory=Collector,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.paths = ProductPaths.resolve(data_home).ensure()
        self.collector_factory = collector_factory
        self.now = now or (lambda: datetime.now(timezone.utc))

    def collect(
        self,
        config_path: str | Path,
        *,
        once: bool,
        hours: float,
        poll_minutes: float,
        log=print,
    ) -> dict[str, object]:
        if once == (hours > 0):
            raise ValueError("collect requires exactly one of --once or --hours")
        if hours < 0 or hours > 24:
            raise ValueError("collect --hours must be in (0,24]")
        if not 0 < poll_minutes <= 1440:
            raise ValueError("collect poll interval must be in (0,1440] minutes")
        config = load_config(config_path)
        _validate_collection_config(config)
        config_sha256 = _sha256(config)
        board_names = list(config["boards"]["enabled"])
        source_projection = {
            "boards": {board: config.get(board, {}) for board in sorted(board_names)},
            "search_terms": config.get("search_terms") or [],
        }
        source_sha256 = _sha256(source_projection)
        started_at = self.now().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        collector = self.collector_factory(config, self.paths.root, log=log)
        cycles = collector.run(hours=hours, poll_minutes=poll_minutes, once=once)
        finished_at = self.now().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        totals = {
            key: sum(int(cycle.get(key, 0)) for cycle in cycles)
            for key in ("seen", "new", "fetched", "errors")
        }
        state_sha256 = _sha256(collector.db.collection_state())
        body: dict[str, object] = {
            "application_authority": False,
            "authority_scope": "collection_only",
            "config_sha256": config_sha256,
            "cycle_count": len(cycles),
            "finished_at": finished_at,
            "mode": "once" if once else "bounded_hours",
            "requested_hours": float(hours),
            "poll_minutes": float(poll_minutes),
            "schema_version": "market-aligner.collection-run-receipt.v1",
            "source_sha256": source_sha256,
            "started_at": started_at,
            "state_sha256": state_sha256,
            "totals": totals,
        }
        receipt_sha256 = _sha256(body)
        receipt = {**body, "receipt_sha256": receipt_sha256}
        receipt_path = self.paths.state / "collection-receipts" / f"{receipt_sha256}.json"
        _write_receipt(receipt_path, receipt)
        return {**receipt, "receipt_path": str(receipt_path)}


class MarketAlignerService:
    def __init__(self, data_home: str | Path | None = None) -> None:
        self.profiles = ProfileStore(data_home)
        self.assessments = AssessmentStore(self.profiles.paths.state / "assessments.sqlite3")

    def assess(
        self,
        request: AssessmentRequest,
        params: ScoringParams | None = None,
    ) -> ScoreResult:
        profile, _evidence = self.profiles.load(request.profile_id)
        result = score(profile, request.job_key, request.track, request.axes, params)
        self.assessments.upsert_score(
            result,
            url=request.url,
            title=request.title,
            company=request.company,
            extraction_confidence=request.extraction_confidence,
        )
        return result

    def gate(self, profile_id: str, job_key: str) -> OpportunityDecision:
        return apply_gate(self.assessments, profile_id, job_key)

    def handoff(
        self,
        profile_id: str,
        job_key: str,
        manifest: Mapping[str, Any],
    ) -> HandoffEnvelope:
        profile, _evidence = self.profiles.load(profile_id)
        return produce_handoff(
            self.assessments,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            job_key=job_key,
            manifest=manifest,
        )
