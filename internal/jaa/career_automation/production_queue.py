"""Fail-closed ascending-fit queue and crash-safe production checkpoints.

Only live, recently verified, eligible vacancies for an admitted provider can
be selected.  Prior consequential or technically blocked attempts are
quarantined.  An incomplete local attempt must be resumed or closed before a
new attempt for the same vacancy can be created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Iterable, Mapping

from .application_archive import (
    ARCHIVE_ROOT_ENV,
    DEFAULT_ARCHIVE_ROOT,
    ApplicationArchive,
    VacancyArchiveIdentity,
)
from .evidence_matching import canonical_json
from .vacancy_identity import canonical_source_url, provider_vacancy_tokens


QUEUE_SCHEMA_VERSION = "jaa.production-queue.v1"
CHECKPOINT_SCHEMA_VERSION = "jaa.production-checkpoint.v1"
ADMITTED_PROVIDERS = frozenset({"greenhouse"})
MAX_LIVE_AGE = timedelta(hours=6)
QUARANTINE_OUTCOMES = frozenset(
    {
        "submitted_success",
        "historical_submitted_success",
        "submitted_failure",
        "indeterminate",
        "blocked",
    }
)
ATTEMPT_ID = re.compile(r"^jaa-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class ProductionQueueError(ValueError):
    """Queue or checkpoint state is unsafe or internally inconsistent."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_identity(value: str) -> str:
    return canonical_source_url(value)


def _provider_tokens(vacancy: VacancyArchiveIdentity) -> frozenset[str]:
    return provider_vacancy_tokens(
        job_key=vacancy.job_key,
        source_url=vacancy.source_url,
    )


def _mentions_provider_token(
    vacancy: VacancyArchiveIdentity, candidate_tokens: frozenset[str]
) -> bool:
    """Recover stable IDs from sparse legacy keys without fuzzy title matching."""
    evidence = f"{vacancy.job_key}\n{vacancy.source_url}".casefold()
    for token in candidate_tokens:
        if token.startswith("url:"):
            continue
        provider, identifier = token.split(":", 1)
        if provider == "workday":
            continue
        if re.search(
            rf"(?<![a-z0-9]){re.escape(identifier.casefold())}(?![a-z0-9])",
            evidence,
        ):
            return True
    return False


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ProductionQueueError(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProductionQueueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _fit(value: object) -> Decimal:
    if isinstance(value, bool):
        raise ProductionQueueError("fit score must be numeric")
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ProductionQueueError("fit score must be numeric") from exc
    if not score.is_finite():
        raise ProductionQueueError("fit score must be finite")
    return score


def _regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ProductionQueueError("checkpoint entry is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            value = handle.read()
        final = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(value) != metadata.st_size
        or final.st_size != metadata.st_size
        or final.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise ProductionQueueError("checkpoint changed while being read")
    return value


def _atomic_create(path: Path, value: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class LiveVacancy:
    vacancy: VacancyArchiveIdentity
    provider: str
    fit_score: Decimal
    live: bool
    eligible: bool
    duplicate: bool
    live_verified_at: str
    scoring_inputs_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.vacancy, VacancyArchiveIdentity):
            raise TypeError("queue vacancy identity is invalid")
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", self.provider):
            raise ProductionQueueError("provider identity is invalid")
        if (
            type(self.live) is not bool
            or type(self.eligible) is not bool
            or type(self.duplicate) is not bool
        ):
            raise ProductionQueueError("queue verdict flags must be booleans")
        object.__setattr__(self, "fit_score", _fit(self.fit_score))
        _parse_time(self.live_verified_at, "live verification time")
        if not HEX_64.fullmatch(self.scoring_inputs_sha256):
            raise ProductionQueueError("scoring-input identity must be SHA-256")

    @classmethod
    def create(
        cls,
        *,
        vacancy: VacancyArchiveIdentity,
        provider: str,
        fit_score: object,
        live: bool,
        eligible: bool,
        duplicate: bool,
        live_verified_at: str,
        scoring_inputs_sha256: str,
    ) -> "LiveVacancy":
        return cls(
            vacancy=vacancy,
            provider=provider,
            fit_score=_fit(fit_score),
            live=live,
            eligible=eligible,
            duplicate=duplicate,
            live_verified_at=live_verified_at,
            scoring_inputs_sha256=scoring_inputs_sha256,
        )


@dataclass(frozen=True)
class PriorAttempt:
    vacancy: VacancyArchiveIdentity
    attempt_id: str
    outcome: str | None
    terminal_manifest_sha256: str | None
    click_intent_present: bool = False
    repairable_preclick_human_verification: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.vacancy, VacancyArchiveIdentity):
            raise TypeError("prior attempt vacancy is invalid")
        if not ATTEMPT_ID.fullmatch(self.attempt_id):
            raise ProductionQueueError("prior attempt identity is invalid")
        if type(self.click_intent_present) is not bool:
            raise ProductionQueueError("click-intent state must be a boolean")
        if type(self.repairable_preclick_human_verification) is not bool:
            raise ProductionQueueError("repairable-block state must be a boolean")
        if self.outcome is None:
            if self.terminal_manifest_sha256 is not None:
                raise ProductionQueueError("incomplete attempt has a terminal hash")
        elif not HEX_64.fullmatch(str(self.terminal_manifest_sha256 or "")):
            raise ProductionQueueError("terminal attempt lacks a valid manifest hash")

    @property
    def incomplete(self) -> bool:
        return self.outcome is None


@dataclass(frozen=True)
class QueueItem:
    vacancy: LiveVacancy
    queue_rank: int
    action: str
    attempt_id: str | None = None


@dataclass(frozen=True)
class QueueExclusion:
    vacancy: LiveVacancy
    reason: str


@dataclass(frozen=True)
class AscendingProductionQueue:
    ready: tuple[QueueItem, ...]
    excluded: tuple[QueueExclusion, ...]
    schema_version: str = QUEUE_SCHEMA_VERSION

    @property
    def next_action(self) -> QueueItem | None:
        return self.ready[0] if self.ready else None


def prior_attempts_from_archive(
    archive: ApplicationArchive,
) -> tuple[PriorAttempt, ...]:
    rows: list[PriorAttempt] = []
    for summary in archive.query():
        attempt = archive.open_attempt(str(summary["attempt_id"]))
        roles = {row.role for row in attempt._objects(attempt._events())}
        terminal_path = attempt.path / "terminal-manifest.json"
        outcome: str | None = None
        terminal_sha256: str | None = None
        terminal: Mapping[str, object] | None = None
        if terminal_path.exists():
            value = _regular_bytes(terminal_path)
            try:
                terminal = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ProductionQueueError("terminal manifest is invalid JSON") from exc
            outcome = str(terminal.get("outcome", ""))
            if (
                terminal.get("attempt_id") != attempt.attempt_id
                or terminal.get("vacancy") != attempt.vacancy.document()
                or not outcome
            ):
                raise ProductionQueueError(
                    "terminal manifest differs from its attempt identity"
                )
            terminal_sha256 = _sha256(value)
        click_intent_present = "submission.click_intent" in roles
        repairable_preclick_human_verification = False
        if outcome == "blocked" and not click_intent_present and terminal is not None:
            selected = terminal.get("selected")
            boundary_sha256 = (
                selected.get("technical.boundary")
                if isinstance(selected, Mapping)
                else None
            )
            boundary_rows = [
                row
                for row in attempt._objects(attempt._events())
                if row.role == "technical.boundary" and row.sha256 == boundary_sha256
            ]
            if len(boundary_rows) == 1:
                boundary_value = _regular_bytes(
                    archive.root / boundary_rows[0].relative_path
                )
                try:
                    boundary = json.loads(boundary_value)
                except json.JSONDecodeError as exc:
                    raise ProductionQueueError(
                        "technical boundary is invalid JSON"
                    ) from exc
                repairable_preclick_human_verification = (
                    _json_bytes(boundary) == boundary_value
                    and boundary.get("classification")
                    in {"human_verification", "human_verification_boundary"}
                    and boundary.get("future_queue") == "technical_boundary"
                )
        rows.append(
            PriorAttempt(
                vacancy=attempt.vacancy,
                attempt_id=attempt.attempt_id,
                outcome=outcome,
                terminal_manifest_sha256=terminal_sha256,
                click_intent_present=click_intent_present,
                repairable_preclick_human_verification=(
                    repairable_preclick_human_verification
                ),
            )
        )
    return tuple(rows)


def build_ascending_queue(
    candidates: Iterable[LiveVacancy],
    *,
    prior_attempts: Iterable[PriorAttempt] = (),
    as_of: datetime | None = None,
    retry_repairable_preclick_blocks: bool = False,
) -> AscendingProductionQueue:
    if type(retry_repairable_preclick_blocks) is not bool:
        raise ProductionQueueError("repairable-block retry policy must be boolean")
    supplied_now = as_of or datetime.now(timezone.utc)
    if supplied_now.tzinfo is None or supplied_now.utcoffset() is None:
        raise ProductionQueueError("queue evaluation time must include a timezone")
    now = supplied_now.astimezone(timezone.utc)
    prior = tuple(prior_attempts)
    candidate_rows = tuple(candidates)
    job_keys = [row.vacancy.job_key for row in candidate_rows]
    vacancy_hashes = [row.vacancy.vacancy_sha256 for row in candidate_rows]
    source_identities = [
        _source_identity(row.vacancy.source_url) for row in candidate_rows
    ]
    provider_tokens = [_provider_tokens(row.vacancy) for row in candidate_rows]
    repeated_provider_identity = any(
        {value for value in left if not value.startswith("url:")}.intersection(
            value for value in right if not value.startswith("url:")
        )
        for index, left in enumerate(provider_tokens)
        for right in provider_tokens[index + 1 :]
    )
    if (
        len(set(job_keys)) != len(job_keys)
        or len(set(vacancy_hashes)) != len(vacancy_hashes)
        or len(set(source_identities)) != len(source_identities)
        or repeated_provider_identity
    ):
        raise ProductionQueueError("queue contains a duplicate vacancy equivalence")
    admitted: list[tuple[LiveVacancy, PriorAttempt | None]] = []
    excluded: list[QueueExclusion] = []
    for candidate in candidate_rows:
        verified_at = _parse_time(candidate.live_verified_at, "live verification time")
        candidate_tokens = _provider_tokens(candidate.vacancy)
        matching = tuple(
            row
            for row in prior
            if (
                row.vacancy.job_key == candidate.vacancy.job_key
                or row.vacancy.vacancy_sha256 == candidate.vacancy.vacancy_sha256
                or _source_identity(row.vacancy.source_url)
                == _source_identity(candidate.vacancy.source_url)
                or bool(_provider_tokens(row.vacancy).intersection(candidate_tokens))
                or _mentions_provider_token(row.vacancy, candidate_tokens)
            )
        )
        incomplete = tuple(row for row in matching if row.incomplete)
        click_intent = tuple(row for row in matching if row.click_intent_present)
        quarantine = tuple(
            row
            for row in matching
            if row.outcome in QUARANTINE_OUTCOMES
            and not (
                retry_repairable_preclick_blocks
                and row.repairable_preclick_human_verification
                and not row.click_intent_present
            )
        )
        reason: str | None = None
        if click_intent:
            reason = "prior_click_intent"
        elif not candidate.live:
            reason = "not_live"
        elif (
            verified_at > now + timedelta(minutes=5) or now - verified_at > MAX_LIVE_AGE
        ):
            reason = "stale_live_verification"
        elif not candidate.eligible:
            reason = "ineligible"
        elif candidate.duplicate:
            reason = "declared_duplicate"
        elif quarantine:
            reason = f"prior_{quarantine[-1].outcome}"
        elif candidate.provider not in ADMITTED_PROVIDERS:
            reason = "unsupported_provider"
        elif len(incomplete) > 1:
            raise ProductionQueueError("vacancy has multiple incomplete attempts")
        if reason is not None:
            excluded.append(QueueExclusion(candidate, reason))
            continue
        admitted.append((candidate, incomplete[0] if incomplete else None))
    admitted.sort(
        key=lambda row: (
            row[0].fit_score,
            row[0].vacancy.job_key,
            row[0].vacancy.vacancy_sha256,
        )
    )
    ready = tuple(
        QueueItem(
            vacancy=candidate,
            queue_rank=index,
            action="resume_attempt" if attempt else "create_attempt",
            attempt_id=attempt.attempt_id if attempt else None,
        )
        for index, (candidate, attempt) in enumerate(admitted, start=1)
    )
    return AscendingProductionQueue(ready=ready, excluded=tuple(excluded))


class ProductionCheckpointLedger:
    """Hash-chained create-only record of starts and terminal checkpoints."""

    def __init__(self, archive: ApplicationArchive) -> None:
        self.archive = archive
        self.path = archive.root / "production-checkpoints"
        if self.path.is_symlink():
            raise ProductionQueueError("checkpoint directory cannot be a symlink")
        self.path.mkdir(mode=0o700, exist_ok=True)
        if self.path.resolve(strict=True).parent != archive.root:
            raise ProductionQueueError("checkpoint directory escapes archive root")
        self.events = self.path / "events"
        if self.events.is_symlink():
            raise ProductionQueueError("checkpoint event directory cannot be a symlink")
        self.events.mkdir(mode=0o700, exist_ok=True)
        self.verify()

    def _paths(self) -> tuple[Path, ...]:
        paths = tuple(sorted(self.events.iterdir(), key=lambda row: row.name))
        for index, path in enumerate(paths, start=1):
            if (
                path.name != f"{index:08d}.json"
                or path.is_symlink()
                or not path.is_file()
            ):
                raise ProductionQueueError(
                    "checkpoint ledger is not a contiguous safe sequence"
                )
        return paths

    def verify(self) -> tuple[Mapping[str, object], ...]:
        rows: list[Mapping[str, object]] = []
        previous: str | None = None
        for index, path in enumerate(self._paths(), start=1):
            value = _regular_bytes(path)
            try:
                row = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ProductionQueueError("checkpoint is invalid JSON") from exc
            if _json_bytes(row) != value:
                raise ProductionQueueError("checkpoint is not canonical JSON")
            claimed = row.get("event_sha256")
            preimage = dict(row)
            preimage.pop("event_sha256", None)
            if (
                row.get("schema_version") != CHECKPOINT_SCHEMA_VERSION
                or row.get("sequence") != index
                or row.get("previous_event_sha256") != previous
                or claimed != _sha256(_json_bytes(preimage))
            ):
                raise ProductionQueueError("checkpoint hash chain is invalid")
            attempt_id = str(row.get("attempt_id", ""))
            if not ATTEMPT_ID.fullmatch(attempt_id):
                raise ProductionQueueError("checkpoint attempt identity is invalid")
            attempt = self.archive.open_attempt(attempt_id)
            if attempt.vacancy.document() != row.get("vacancy"):
                raise ProductionQueueError(
                    "checkpoint vacancy differs from its attempt"
                )
            event_type = row.get("event_type")
            if event_type == "attempt_terminal":
                terminal_path = attempt.path / "terminal-manifest.json"
                terminal = json.loads(_regular_bytes(terminal_path))
                if row.get("outcome") != terminal.get("outcome") or row.get(
                    "terminal_manifest_sha256"
                ) != _sha256(_regular_bytes(terminal_path)):
                    raise ProductionQueueError(
                        "terminal checkpoint differs from its archive"
                    )
            elif event_type != "attempt_started":
                raise ProductionQueueError("checkpoint event type is unsupported")
            rows.append(row)
            previous = str(claimed)
        return tuple(rows)

    def _append(self, payload: Mapping[str, object]) -> str:
        rows = self.verify()
        sequence = len(rows) + 1
        document = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "sequence": sequence,
            "previous_event_sha256": (rows[-1]["event_sha256"] if rows else None),
            "occurred_at": _utc_now(),
            **payload,
        }
        event_sha256 = _sha256(_json_bytes(document))
        document["event_sha256"] = event_sha256
        _atomic_create(self.events / f"{sequence:08d}.json", _json_bytes(document))
        self.verify()
        return event_sha256

    def record_attempt_started(self, attempt_id: str) -> str:
        attempt = self.archive.open_attempt(attempt_id)
        if (attempt.path / "terminal-manifest.json").exists():
            raise ProductionQueueError("cannot start an already terminal attempt")
        rows = self.verify()
        if any(row["attempt_id"] == attempt_id for row in rows):
            raise ProductionQueueError("attempt already has a production checkpoint")
        return self._append(
            {
                "event_type": "attempt_started",
                "attempt_id": attempt_id,
                "vacancy": attempt.vacancy.document(),
            }
        )

    def record_attempt_terminal(self, attempt_id: str) -> str:
        attempt = self.archive.open_attempt(attempt_id)
        terminal_path = attempt.path / "terminal-manifest.json"
        terminal_bytes = _regular_bytes(terminal_path)
        terminal = json.loads(terminal_bytes)
        rows = self.verify()
        started = [
            row
            for row in rows
            if row["attempt_id"] == attempt_id
            and row["event_type"] == "attempt_started"
        ]
        completed = [
            row
            for row in rows
            if row["attempt_id"] == attempt_id
            and row["event_type"] == "attempt_terminal"
        ]
        if len(started) != 1 or completed:
            raise ProductionQueueError("attempt checkpoint lifecycle is invalid")
        return self._append(
            {
                "event_type": "attempt_terminal",
                "attempt_id": attempt_id,
                "vacancy": attempt.vacancy.document(),
                "outcome": terminal["outcome"],
                "terminal_manifest_sha256": _sha256(terminal_bytes),
            }
        )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-root",
        type=Path,
        default=Path(os.environ.get(ARCHIVE_ROOT_ENV, DEFAULT_ARCHIVE_ROOT)),
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    archive = ApplicationArchive(
        arguments.archive_root,
        repository_root=arguments.repository_root,
        create=False,
    )
    ledger = ProductionCheckpointLedger(archive)
    print(
        canonical_json(
            {
                "schema_version": CHECKPOINT_SCHEMA_VERSION,
                "verified": True,
                "event_count": len(ledger.verify()),
                "attempt_count": len(prior_attempts_from_archive(archive)),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "AscendingProductionQueue",
    "LiveVacancy",
    "PriorAttempt",
    "ProductionCheckpointLedger",
    "ProductionQueueError",
    "QueueExclusion",
    "QueueItem",
    "build_ascending_queue",
    "prior_attempts_from_archive",
]
