"""In-process service API shared by CLI and future local transports."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from market_aligner.applications.handoff import HandoffEnvelope
from market_aligner.applications.producer import produce_handoff
from market_aligner.applications.assessment_promotion import (
    AssessmentPromotion,
    promote_current_processing_assessment,
)
from market_aligner.assessment.opportunity import OpportunityDecision, apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, ScoreResult, ScoringParams, score
from market_aligner.collectors.engine import Collector
from market_aligner.config import ProductPaths
from market_aligner.config_loader import closure_identity, load_config, snapshot_config
from market_aligner.profiler.store import ProfileStore
from market_aligner.research.store import AssessmentStore
from market_aligner.state.vacancies import JobDatabase
from market_aligner.state.operations import (
    INGEST_CYCLE_KIND,
    OperationJournal,
    OperationRefused,
    canonical_json as operation_canonical_json,
    make_record,
    new_owner_id,
    normalized_error,
    utc_now,
    validate_operation_id,
)


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
        for directory in (path.parent.absolute(), *path.parent.absolute().parents):
            directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            if directory == directory.parent:
                break
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
        operation_id: str,
        log=print,
    ) -> dict[str, object]:
        validate_operation_id(operation_id)
        if once == (hours > 0):
            raise ValueError("collect requires exactly one of --once or --hours")
        if hours < 0 or hours > 24:
            raise ValueError("collect --hours must be in (0,24]")
        if not 0 < poll_minutes <= 1440:
            raise ValueError("collect poll interval must be in (0,1440] minutes")
        config_source = Path(config_path).expanduser().resolve(strict=True)
        config, config_identities = snapshot_config(config_source)
        _validate_collection_config(config)
        config_sha256 = _sha256(config)
        config_file_sha256 = closure_identity(config_identities)
        board_names = sorted(config["boards"]["enabled"])
        source_projection = {
            "boards": {board: config.get(board, {}) for board in sorted(board_names)},
            "search_terms": config.get("search_terms") or [],
        }
        source_sha256 = _sha256(source_projection)
        journal = OperationJournal(self.paths.state / "operations")
        binding = {
            "kind": INGEST_CYCLE_KIND,
            "config_source": str(config_source),
            "config_file_sha256": config_file_sha256,
            "config_sha256": config_sha256,
            "source_scope": board_names,
            "data_home": str(self.paths.root),
        }

        def replay_or_refuse(record: dict[str, object]) -> dict[str, object]:
            mismatches = [
                key
                for key, expected in binding.items()
                if record.get(key) != expected
            ]
            if mismatches:
                raise OperationRefused(
                    "operation_binding_changed",
                    "operation ID is already bound to different exact inputs: "
                    + ", ".join(sorted(mismatches)),
                    operation_id=operation_id,
                    disposition=str(record.get("disposition")),
                )
            disposition = str(record["disposition"])
            if disposition in {"completed", "failed"}:
                return {
                    "application_authority": False,
                    "authority_scope": "collection_only",
                    "schema_version": "market-aligner.collection-operation-replay.v1",
                    "operation_id": operation_id,
                    "disposition": disposition,
                    "receipt_id": record["receipt_id"],
                    "replayed": True,
                    "result": record["result"],
                    "error": record["error"],
                    "source_scope": record["source_scope"],
                }
            raise OperationRefused(
                "indeterminate_state" if disposition == "indeterminate" else "in_progress",
                "operation has an unresolved external-call state and cannot be replayed",
                operation_id=operation_id,
                disposition=disposition,
            )

        existing = journal.load(operation_id)
        if existing is not None:
            return replay_or_refuse(existing)
        locks = journal.acquire_board_locks(str(self.paths.root), board_names)
        operation_lock_fd: int | None = None
        try:
            blockers = journal.scan_unresolved_scope_blockers(
                str(self.paths.root), board_names
            )
            if blockers:
                raise OperationRefused(
                    "scope_blocked",
                    "an unresolved earlier collection intersects this board scope",
                    extra={"blocked_by": blockers},
                )
            operation_lock_fd = journal.open_operation_lock(operation_id)
            current = journal.load(
                operation_id, operation_lock_fd=operation_lock_fd
            )
            if current is not None:
                return replay_or_refuse(current)
            claim = make_record(
                operation_id=operation_id,
                disposition="in_flight",
                owner_id=new_owner_id(),
                **binding,
            )
            claim_bytes = operation_canonical_json(claim).encode("utf-8")
            if not journal.claim(claim):
                raise OperationRefused(
                    "in_progress",
                    "another process won the exact operation claim",
                    operation_id=operation_id,
                    disposition="in_flight",
                )
            started_at = self.now().astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            collector = self.collector_factory(config, self.paths.root, log=log)
            try:
                cycles = collector.run(
                    hours=hours,
                    poll_minutes=poll_minutes,
                    once=once,
                )
            except Exception as exc:
                failed = make_record(
                    operation_id=operation_id,
                    disposition="failed",
                    owner_id=str(claim["owner_id"]),
                    started_at=str(claim["started_at"]),
                    finished_at=utc_now(),
                    error=normalized_error(exc),
                    **binding,
                )
                journal.cas_replace(
                    failed,
                    claim_bytes,
                    operation_id=operation_id,
                    operation_lock_fd=operation_lock_fd,
                )
                raise
            finished_at = self.now().astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            totals = {
                key: sum(int(cycle.get(key, 0)) for cycle in cycles)
                for key in ("seen", "new", "fetched", "errors")
            }
            operation_result = {**totals, "database_total": (
                int(cycles[-1].get("database_total", 0)) if cycles else 0
            )}
            completed = make_record(
                operation_id=operation_id,
                disposition="completed",
                owner_id=str(claim["owner_id"]),
                started_at=str(claim["started_at"]),
                finished_at=utc_now(),
                result=operation_result,
                **binding,
            )
            journal.cas_replace(
                completed,
                claim_bytes,
                operation_id=operation_id,
                operation_lock_fd=operation_lock_fd,
            )
        finally:
            if operation_lock_fd is not None:
                OperationJournal.release_locks([operation_lock_fd])
            OperationJournal.release_locks(locks)
        state_sha256 = _sha256(collector.db.collection_state())
        body: dict[str, object] = {
            "application_authority": False,
            "authority_scope": "collection_only",
            "config_sha256": config_sha256,
            "config_file_sha256": config_file_sha256,
            "cycle_count": len(cycles),
            "finished_at": finished_at,
            "mode": "once" if once else "bounded_hours",
            "requested_hours": float(hours),
            "poll_minutes": float(poll_minutes),
            "schema_version": "market-aligner.collection-run-receipt.v1",
            "operation_id": operation_id,
            "operation_receipt_id": completed["receipt_id"],
            "replayed": False,
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

    def refresh_vacancy(
        self,
        config_path: str | Path,
        *,
        job_key: str,
        expected_content_sha256: str,
        operation_id: str,
        log=print,
    ) -> dict[str, object]:
        """Refresh exactly one configured existing vacancy under a SQLite CAS."""

        if not job_key or ":" not in job_key:
            raise ValueError("refresh requires an exact board-qualified job key")
        if len(expected_content_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in expected_content_sha256
        ):
            raise ValueError("expected content identity must be lowercase SHA-256")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", operation_id) is None:
            raise ValueError("refresh operation ID must be a stable opaque token")
        config = load_config(config_path)
        _validate_collection_config(config)
        board = job_key.split(":", 1)[0]
        if board not in config["boards"]["enabled"]:
            raise ValueError(f"vacancy board is not enabled by collection config: {board}")
        config_sha256 = _sha256(config)
        source_sha256 = _sha256(
            {
                "adapter": board,
                "adapter_config": config.get(board, {}) or {},
                "job_key": job_key,
            }
        )
        refresh_context = {
            "config_sha256": config_sha256,
            "expected_content_sha256": expected_content_sha256,
            "job_key": job_key,
            "operation_id": operation_id,
            "schema_version": "market-aligner.vacancy-refresh-context.v1",
            "source_sha256": source_sha256,
        }
        context_sha256 = _sha256(refresh_context)
        refresh_id = _sha256(
            {
                "context_sha256": context_sha256,
                "schema_version": "market-aligner.vacancy-refresh-id.v1",
            }
        )
        started_at = self.now().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        collector = self.collector_factory(config, self.paths.root, log=log)
        receipt_context: dict[str, object] = {
            "adapter": board,
            "application_authority": False,
            "authority_scope": "collection_only",
            "config_sha256": config_sha256,
            "context_sha256": context_sha256,
            "expected_old_content_sha256": expected_content_sha256,
            "fallback_engine": None,
            "job_key": job_key,
            "official_fetch_count": 1,
            "operation_id": operation_id,
            "refresh_id": refresh_id,
            "schema_version": "market-aligner.vacancy-refresh-receipt.v3",
            "source_sha256": source_sha256,
            "started_at": started_at,
        }
        refreshed = collector.refresh_vacancy(
            job_key,
            expected_content_sha256=expected_content_sha256,
            operation_id=operation_id,
            refresh_id=refresh_id,
            context_sha256=context_sha256,
            operation_context=refresh_context,
            started_at=started_at,
            receipt_context=receipt_context,
            finished_at=lambda: self.now().astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        )
        raw_path = Path(str(refreshed.pop("raw_cache_path_absolute"))).resolve()
        try:
            raw_path.relative_to(self.paths.root.resolve())
        except ValueError as exc:
            raise ValueError("collector raw cache escaped the external data home") from exc
        if hashlib.sha256(raw_path.read_bytes()).hexdigest() != refreshed.get(
            "raw_cache_file_sha256"
        ):
            raise ValueError("materialized raw cache differs from sealed refresh transition")
        body = dict(refreshed)
        receipt_sha256 = _sha256(body)
        receipt = {**body, "receipt_sha256": receipt_sha256}
        receipt_path = (
            self.paths.state / "collection-refresh-receipts" / f"{receipt_sha256}.json"
        )
        _write_receipt(receipt_path, receipt)
        return {**receipt, "receipt_path": str(receipt_path)}


class MarketAlignerService:
    def __init__(self, data_home: str | Path | None = None) -> None:
        self.profiles = ProfileStore(data_home)
        self.assessments = AssessmentStore(self.profiles.paths.state / "assessments.sqlite3")
        self.jobs = JobDatabase(self.profiles.paths.state / "vacancies.sqlite3")

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

    @staticmethod
    def prepare_internal_jaa(
        *,
        eligibility_receipt: bytes,
        evidence_reference_sha256: str,
        contact_reference_sha256: str,
        forensic_root: Path,
        attempt_id: str,
        application_id: str,
        ats_name: str = "fixture",
        backend=None,
    ) -> dict[str, object]:
        """Run only the faceless, zero-interaction Market-to-JAA corridor."""
        from market_aligner.applications.jaa import capture_or_recover, prepare_from_market

        source, sanity = prepare_from_market(
            eligibility_receipt=eligibility_receipt,
            evidence_reference_sha256=evidence_reference_sha256,
            contact_reference_sha256=contact_reference_sha256,
        )
        forensic = capture_or_recover(
            root=forensic_root,
            attempt_id=attempt_id,
            application_id=application_id,
            source=source,
            sanity=sanity,
            ats_name=ats_name,
            backend=backend,
        )
        return {
            "schema_version": "market-aligner.internal-jaa-result.v1",
            "status": forensic.outcome,
            "source": source.document(),
            "sanity_receipt_sha256": sanity.receipt_sha256,
            "forensic_receipt": forensic.document(),
            "identity_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }

    @staticmethod
    def process_one(
        data_home: Path,
        envelope_name: str,
        *,
        supplied_operation_id: str,
        supplied_config_path: str,
        supplied_profile_id: str,
        supplied_job_key: str,
        supplied_track: str,
    ) -> bytes:
        """Run FIT-001 through the no-create retained admission seam."""
        from market_aligner.processing import process_one

        return process_one(
            data_home,
            envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track,
        )

    @staticmethod
    def eligibility_one(
        data_home: Path,
        envelope_name: str,
        *,
        supplied_operation_id: str,
        supplied_fit_operation_id: str,
        supplied_config_path: str,
        supplied_profile_id: str,
        supplied_job_key: str,
        supplied_track: str,
    ) -> bytes:
        """Run ELIGIBILITY-001 without constructing the mutating service."""
        from market_aligner.processing import eligibility_one

        return eligibility_one(
            data_home,
            envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_fit_operation_id=supplied_fit_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track,
        )

    def promote_processing(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        processing_receipt_path: Path,
    ) -> AssessmentPromotion:
        return promote_current_processing_assessment(
            jobs=self.jobs,
            assessments=self.assessments,
            processing_receipt_path=processing_receipt_path,
            profile_id=profile_id,
            track=track,
            job_key=job_key,
            receipt_root=(
                self.profiles.paths.state / "assessment-promotion-receipts"
            ),
        )

    def handoff(
        self,
        profile_id: str,
        job_key: str,
        manifest: Mapping[str, Any],
        *,
        handoff_job_key: str | None = None,
    ) -> HandoffEnvelope:
        profile, _evidence = self.profiles.load(profile_id)
        return produce_handoff(
            self.assessments,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            job_key=job_key,
            manifest=manifest,
            handoff_job_key=handoff_job_key,
        )
