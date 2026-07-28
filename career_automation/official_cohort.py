"""Build an exact JAA-04 queue from live, configured official authorities.

The canonical collector configuration supplies ``boards.enabled`` and the
top-level board sections. This command projects its supported official ATS
adapters; enabled discovery-only boards never become evidence authorities.
Every HTTP response consumed by an adapter is retained byte-for-byte.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit, urlunsplit

from career_automation.employer_research import (
    FRESHNESS_DAYS, IntelligenceKind, RawResponseCache,
    _public_transport_url, _public_url, extract_publisher_timestamps,
)
from career_automation.holdout_firewall import (
    QuarantineIndex,
    load_quarantine_index,
)
from career_automation.opportunity_calibration import (
    DECISION_RULE_VERSION, CalibrationPolicy, Confidence, Opportunity0Input,
    calibration_policy_json, decide_opportunity0,
)
from career_automation.public_access import (
    PublicAccessController,
    PublicAccessPolicy,
    USER_AGENT,
)
from scraper.scrapling_client import ScraplingClient
from scraper.adapters.base import load_adapter
from scraper.viability import Vacancy, canonical_key, local_decision
from skeleton.configuration import load_config
from tracked_source_revision import source_git_revision

COHORT_SIZE = 30
OFFICIAL_ADAPTERS = frozenset({
    "ashby", "greenhouse", "lever", "personio", "recruitee",
    "smartrecruiters", "workable", "workday",
})
AGGREGATORS = frozenset({
    "adzuna", "arbeitnow", "himalayas", "jobicy", "jooble", "muse",
    "reed", "remotefirst", "remoteok", "remotive", "weworkremotely",
})
VACANCY_FRESHNESS_DAYS = FRESHNESS_DAYS[IntelligenceKind.ROLE]
if VACANCY_FRESHNESS_DAYS != FRESHNESS_DAYS[IntelligenceKind.HIRING]:
    raise RuntimeError("ROLE and HIRING vacancy freshness policies differ")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _normal_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(),
                       parts.path.rstrip("/"), "", ""))


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, body: bytes, *, mode: int = 0o600) -> None:
    """Write one non-existing artifact through fsynced temp-file replacement."""
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


class JournalReplayFailure(RuntimeError):
    """A response-less failure retained by a durable request journal."""


class DurableRequestJournal:
    """Append-only request/response checkpoint for official discovery.

    Each external request receives a stable request sequence before transport.
    A second fsynced record binds a successful response to its exact raw bytes
    (or retains the transport failure). Resume validates the event hash chain,
    run identity and the complete raw inventory before replaying preserved
    responses through the normal adapter code.
    """

    SCHEMA_VERSION = "jaa04.request-journal.v1"
    IDENTITY_SCHEMA_VERSION = "jaa04.request-journal-identity.v1"

    def __init__(
        self,
        run_root: Path,
        raw_root: Path,
        identity: dict[str, Any],
        *,
        resume: bool,
    ) -> None:
        self.run_root = run_root
        self.raw_root = raw_root
        self.identity_path = run_root / "request-journal-identity.json"
        self.path = run_root / "request-journal.jsonl"
        self.identity = identity
        self.resume = resume
        self._lock = threading.RLock()
        self._events: list[dict[str, Any]] = []
        self._starts: list[dict[str, Any]] = []
        self._outcomes: dict[int, dict[str, Any]] = {}
        self._consumed: set[int] = set()
        self._replay_cursor = 0
        self._next_request_sequence = 0
        self._previous_entry_sha256: str | None = None
        if resume:
            self._load_and_validate()
        else:
            self._create()

    @classmethod
    def open(
        cls,
        *,
        config_path: Path,
        policy_sha256: str,
        quarantine_index_sha256: str,
        source_head: str,
        raw_root: Path,
        resume: bool,
    ) -> "DurableRequestJournal":
        run_root = raw_root.parent
        identity = {
            "schema_version": cls.IDENTITY_SCHEMA_VERSION,
            "configuration_sha256": hashlib.sha256(
                config_path.read_bytes()
            ).hexdigest(),
            "access_policy_sha256": policy_sha256,
            "failed_holdout_quarantine_index_sha256": quarantine_index_sha256,
            "source_head": source_head,
            "raw_root": raw_root.name,
        }
        return cls(run_root, raw_root, identity, resume=resume)

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.identity)).hexdigest()

    @property
    def journal_sha256(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def preserved_response_count(self) -> int:
        return sum(
            row.get("event") == "response_preserved"
            for row in self._events
        )

    def _create(self) -> None:
        self.run_root.mkdir(parents=True, exist_ok=True)
        existing_inventory, _ = _raw_inventory(self.raw_root)
        if existing_inventory:
            raise RuntimeError(
                "new request journal refuses a non-empty raw store"
            )
        if self.identity_path.exists() or self.identity_path.is_symlink():
            raise RuntimeError("request journal identity already exists")
        if self.path.exists() or self.path.is_symlink():
            raise RuntimeError("request journal already exists")
        _atomic_write(
            self.identity_path,
            _canonical(self.identity) + b"\n",
        )
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.path.parent)

    @staticmethod
    def _entry_hash(row: dict[str, Any]) -> str:
        hashed = dict(row)
        hashed.pop("entry_sha256", None)
        return hashlib.sha256(_canonical(hashed)).hexdigest()

    def _load_and_validate(self) -> None:
        if not self.identity_path.is_file() or not self.path.is_file():
            raise RuntimeError(
                "resume requires the request journal and identity"
            )
        try:
            actual_identity = json.loads(
                self.identity_path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("request journal identity is invalid") from exc
        if actual_identity != self.identity:
            raise RuntimeError(
                "request journal configuration, policy, quarantine index, "
                "HEAD or raw root mismatch"
            )
        previous: str | None = None
        starts: dict[int, dict[str, Any]] = {}
        outcomes: dict[int, dict[str, Any]] = {}
        raw_lines = self.path.read_bytes().splitlines()
        for expected_event_sequence, raw_line in enumerate(raw_lines):
            try:
                row = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("request journal row is invalid") from exc
            if (
                not isinstance(row, dict)
                or row.get("schema_version") != self.SCHEMA_VERSION
                or row.get("event_sequence") != expected_event_sequence
                or row.get("previous_entry_sha256") != previous
                or row.get("entry_sha256") != self._entry_hash(row)
            ):
                raise RuntimeError("request journal hash chain is invalid")
            request_sequence = row.get("request_sequence")
            if not isinstance(request_sequence, int) or request_sequence < 0:
                raise RuntimeError("request journal sequence is invalid")
            event = row.get("event")
            if event == "request_started":
                if request_sequence in starts or request_sequence != len(starts):
                    raise RuntimeError(
                        "request journal request sequence is not monotonic"
                    )
                starts[request_sequence] = row
            elif event in {
                "response_preserved",
                "request_failed",
                "request_abandoned_on_resume",
            }:
                if request_sequence not in starts:
                    raise RuntimeError(
                        "request journal outcome has no start record"
                    )
                prior = outcomes.get(request_sequence)
                if prior is not None and prior.get("event") != "request_failed":
                    raise RuntimeError(
                        "request journal has duplicate terminal outcomes"
                    )
                outcomes[request_sequence] = row
            else:
                raise RuntimeError("request journal event type is invalid")
            self._events.append(row)
            previous = str(row["entry_sha256"])
        self._starts = [starts[index] for index in sorted(starts)]
        self._outcomes = outcomes
        self._next_request_sequence = len(self._starts)
        self._previous_entry_sha256 = previous
        self._validate_raw_inventory()

    def _validate_raw_inventory(self) -> None:
        expected: dict[str, dict[str, Any]] = {}
        for outcome in self._outcomes.values():
            if outcome.get("event") != "response_preserved":
                continue
            raw_files = outcome.get("raw_files")
            if not isinstance(raw_files, list) or not raw_files:
                raise RuntimeError(
                    "preserved journal response has no raw files"
                )
            for row in raw_files:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("path"), str)
                    or not isinstance(row.get("byte_count"), int)
                    or not isinstance(row.get("sha256"), str)
                ):
                    raise RuntimeError(
                        "request journal raw inventory row is invalid"
                    )
                prior = expected.get(row["path"])
                if prior is not None and prior != row:
                    raise RuntimeError(
                        "request journal aliases conflicting raw bytes"
                    )
                expected[row["path"]] = row
        actual, actual_hash = _raw_inventory(self.raw_root)
        expected_rows = [expected[path] for path in sorted(expected)]
        expected_hash = hashlib.sha256(_canonical(expected_rows)).hexdigest()
        if actual != expected_rows or actual_hash != expected_hash:
            raise RuntimeError(
                "request journal raw inventory hash mismatch"
            )

    def _append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            row = {
                "schema_version": self.SCHEMA_VERSION,
                "event_sequence": len(self._events),
                "previous_entry_sha256": self._previous_entry_sha256,
                **payload,
            }
            row["entry_sha256"] = self._entry_hash(row)
            encoded = _canonical(row) + b"\n"
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND)
            with os.fdopen(descriptor, "ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            self._events.append(row)
            self._previous_entry_sha256 = row["entry_sha256"]
            return row

    def start_request(
        self,
        kind: str,
        requested_url: str,
        *,
        requested_at: str,
    ) -> int:
        if kind not in {"content", "robots"}:
            raise ValueError("journal request kind is invalid")
        with self._lock:
            sequence = self._next_request_sequence
            self._next_request_sequence += 1
            row = self._append({
                "event": "request_started",
                "request_sequence": sequence,
                "request_kind": kind,
                "requested_url": requested_url,
                "requested_at": requested_at,
            })
            self._starts.append(row)
            return sequence

    def preserve_response(
        self,
        request_sequence: int,
        *,
        status: int,
        observed_at: str,
        final_url: str,
        raw_files: list[dict[str, Any]],
        replay_payload: dict[str, Any],
        consumed_request_sequences: list[int] | None = None,
    ) -> dict[str, Any]:
        if request_sequence in self._outcomes:
            raise RuntimeError("journal request already has an outcome")
        row = self._append({
            "event": "response_preserved",
            "request_sequence": request_sequence,
            "status": status,
            "observed_at": observed_at,
            "final_url": final_url,
            "raw_files": raw_files,
            "consumed_request_sequences": (
                consumed_request_sequences or [request_sequence]
            ),
            "replay_payload": replay_payload,
        })
        self._outcomes[request_sequence] = row
        if self.resume:
            self._consumed.add(request_sequence)
        return row

    def preserve_failure(
        self,
        request_sequence: int,
        *,
        observed_at: str,
        error_type: str,
        error_message: str,
    ) -> None:
        if request_sequence in self._outcomes:
            raise RuntimeError("journal request already has an outcome")
        row = self._append({
            "event": "request_failed",
            "request_sequence": request_sequence,
            "observed_at": observed_at,
            "error_type": error_type,
            "error_message": error_message,
        })
        self._outcomes[request_sequence] = row
        if self.resume:
            self._consumed.add(request_sequence)

    def _advance_cursor(self) -> None:
        while (
            self._replay_cursor < len(self._starts)
            and int(
                self._starts[self._replay_cursor]["request_sequence"]
            ) in self._consumed
        ):
            self._replay_cursor += 1

    def next_replay_kind(self) -> str | None:
        if not self.resume:
            return None
        with self._lock:
            self._advance_cursor()
            if self._replay_cursor >= len(self._starts):
                return None
            value = self._starts[self._replay_cursor].get("request_kind")
            return str(value) if value is not None else None

    def replay(
        self,
        kind: str,
        requested_url: str,
    ) -> dict[str, Any] | None:
        """Return a preserved completion, or None for a crashed request."""
        if not self.resume:
            return None
        with self._lock:
            self._advance_cursor()
            if self._replay_cursor >= len(self._starts):
                return None
            start = self._starts[self._replay_cursor]
            sequence = int(start["request_sequence"])
            if (
                start.get("request_kind") != kind
                or start.get("requested_url") != requested_url
            ):
                raise RuntimeError(
                    "resume request diverges from the durable journal"
                )
            outcome = self._outcomes.get(sequence)
            if outcome is None:
                row = self._append({
                    "event": "request_abandoned_on_resume",
                    "request_sequence": sequence,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "reason": "no_preserved_response",
                })
                self._outcomes[sequence] = row
                self._consumed.add(sequence)
                self._advance_cursor()
                return None
            event = outcome.get("event")
            if event == "request_failed":
                self._consumed.add(sequence)
                self._advance_cursor()
                raise JournalReplayFailure(
                    "journalled request failure: "
                    f"{outcome.get('error_type')}: "
                    f"{outcome.get('error_message')}"
                )
            if event == "request_abandoned_on_resume":
                self._consumed.add(sequence)
                self._advance_cursor()
                return None
            consumed = outcome.get("consumed_request_sequences")
            if (
                event != "response_preserved"
                or not isinstance(consumed, list)
                or sequence not in consumed
                or any(
                    not isinstance(value, int) or value < 0
                    for value in consumed
                )
            ):
                raise RuntimeError("journal replay outcome is invalid")
            for value in consumed:
                if value >= len(self._starts):
                    raise RuntimeError(
                        "journal replay consumes an unknown request"
                    )
                self._consumed.add(value)
            self._advance_cursor()
            return outcome

    def completions_for(
        self,
        request_sequences: list[int],
    ) -> list[dict[str, Any]]:
        selected = {
            sequence: self._outcomes[sequence]
            for sequence in request_sequences
            if (
                sequence in self._outcomes
                and self._outcomes[sequence].get("event")
                == "response_preserved"
            )
        }
        return sorted(
            selected.values(),
            key=lambda row: int(row["event_sequence"]),
        )

    def assert_replay_consumed(self) -> None:
        if not self.resume:
            return
        unconsumed = [
            int(row["request_sequence"])
            for row in self._starts
            if int(row["request_sequence"]) not in self._consumed
        ]
        if unconsumed:
            raise RuntimeError(
                "resume completed before consuming the durable journal"
            )

    def evidence(self) -> dict[str, Any]:
        self._validate_raw_inventory()
        inventory, inventory_hash = _raw_inventory(self.raw_root)
        return {
            "schema_version": self.SCHEMA_VERSION,
            "identity_path": str(self.identity_path),
            "identity_sha256": self.identity_sha256,
            "journal_path": str(self.path),
            "journal_sha256": self.journal_sha256,
            "event_count": self.event_count,
            "preserved_response_count": self.preserved_response_count,
            "raw_inventory_sha256": inventory_hash,
            "raw_file_count": len(inventory),
        }


class ResponseRecorder:
    """Record response bodies and redirect chains without changing adapters."""

    def __init__(
        self,
        root: Path,
        access_controller: Any,
        *,
        journal: DurableRequestJournal | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.root = root
        self.access_controller = access_controller
        self.journal = journal
        self.clock_ns = clock_ns
        self.sleeper = sleeper
        self.root.mkdir(parents=True, exist_ok=True)
        self.records: list[dict[str, Any]] = []
        self.send_events: list[dict[str, Any]] = []
        self._send_context_by_url: dict[str, dict[str, Any]] = {}
        self._last_actual_send_ns: dict[str, int] = {}
        self._send_lock = threading.Lock()

    def record(
        self,
        response: Any,
        observed_at: str,
        *,
        access_receipt: Any,
        send_sequence: int,
        dns_addresses: tuple[str, ...],
        journal_request_sequence: int | None = None,
    ) -> tuple[list[dict[str, Any]], list[int]]:
        chain = [*response.history, response]
        redirect_chain = [str(item.url) for item in chain]
        added: list[dict[str, Any]] = []
        consumed_journal_sequences: set[int] = set()
        for sequence, item in enumerate(chain):
            item_requested_url = str(item.request.url)
            context = self._send_context_by_url.get(item_requested_url)
            item_receipt = (
                context["access_receipt"] if context is not None
                else access_receipt
            )
            item_send_sequence = (
                int(context["send_sequence"]) if context is not None
                else send_sequence
            )
            item_dns_addresses = (
                tuple(context["dns_addresses"]) if context is not None
                else dns_addresses
            )
            item_journal_sequence = (
                context.get("journal_request_sequence")
                if context is not None
                else journal_request_sequence
            )
            if isinstance(item_journal_sequence, int):
                consumed_journal_sequences.add(item_journal_sequence)
            body = bytes(item.content)
            digest = hashlib.sha256(body).hexdigest()
            relative = Path(digest[:2]) / f"{digest}.response"
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("raw response hash collision")
            if not path.exists():
                _atomic_write(path, body, mode=0o444)
            published_at, updated_at, publisher_evidence = (
                extract_publisher_timestamps(body)
            )
            record = {
                "sha256": digest, "raw_response": relative.as_posix(),
                "requested_url": item_requested_url, "final_url": str(response.url),
                "response_url": str(item.url), "status": int(item.status_code),
                "redirect_sequence": sequence, "redirect_chain": redirect_chain,
                "observed_at": observed_at,
                "byte_count": len(body),
                "dns_addresses": list(item_dns_addresses),
                "send_sequence": item_send_sequence,
                "published_at": published_at,
                "updated_at": updated_at,
                "publisher_time": updated_at or published_at,
                "publisher_date_evidence": publisher_evidence,
                "retrieval_engine": "requests-static",
                "access_receipt": asdict(item_receipt),
            }
            self.records.append(record)
            added.append(record)
        return added, sorted(consumed_journal_sequences)

    def _restore_completion(self, completion: dict[str, Any]) -> None:
        payload = completion.get("replay_payload")
        if not isinstance(payload, dict):
            raise RuntimeError("journal content replay payload is invalid")
        records = payload.get("raw_response_records")
        send_event = payload.get("send_event")
        if (
            not isinstance(records, list)
            or not all(isinstance(row, dict) for row in records)
            or not isinstance(send_event, dict)
        ):
            raise RuntimeError("journal content replay evidence is invalid")
        self.records.extend(dict(row) for row in records)
        sequence = send_event.get("send_sequence")
        if (
            not isinstance(sequence, int)
            or any(
                row.get("send_sequence") == sequence
                for row in self.send_events
            )
        ):
            raise RuntimeError("journal content send sequence is invalid")
        self.send_events.append(dict(send_event))
        self.send_events.sort(key=lambda row: int(row["send_sequence"]))

    def _response_from_completion(
        self,
        completion: dict[str, Any],
        request: Any,
    ) -> Any:
        import requests

        payload = completion.get("replay_payload")
        chain = payload.get("response_chain") if isinstance(payload, dict) else None
        if not isinstance(chain, list) or not chain:
            raise RuntimeError("journal response chain is invalid")
        responses: list[Any] = []
        for index, row in enumerate(chain):
            if not isinstance(row, dict):
                raise RuntimeError("journal response chain row is invalid")
            reference = Path(str(row.get("raw_response", "")))
            target = (self.root / reference).resolve()
            if self.root.resolve() not in target.parents or not target.is_file():
                raise RuntimeError("journal response bytes are unavailable")
            body = target.read_bytes()
            if hashlib.sha256(body).hexdigest() != row.get("sha256"):
                raise RuntimeError("journal response bytes changed")
            restored = requests.Response()
            restored.status_code = int(row["status"])
            restored._content = body
            restored.url = str(row["response_url"])
            restored.headers.update(
                dict(row.get("headers") or {})
            )
            if index == len(chain) - 1:
                restored.request = request
            else:
                restored.request = requests.Request(
                    str(row.get("method") or "GET"),
                    str(row["requested_url"]),
                ).prepare()
            restored.history = list(responses)
            responses.append(restored)
        return responses[-1]

    @contextmanager
    def installed(self) -> Iterator[None]:
        import requests

        original = requests.sessions.Session.send
        recorder = self

        def send(session: Any, request: Any, **kwargs: Any) -> Any:
            requested_url = str(request.url)
            if recorder.journal is not None:
                if recorder.journal.next_replay_kind() == "robots":
                    authorize_replay = getattr(
                        recorder.access_controller,
                        "authorize_replay",
                        None,
                    )
                    if authorize_replay is None:
                        raise RuntimeError(
                            "resume requires audited robots replay"
                        )
                    authorize_replay(requested_url)
                completion = recorder.journal.replay(
                    "content",
                    requested_url,
                )
                if completion is not None:
                    consumed = list(
                        completion["consumed_request_sequences"]
                    )
                    for preserved in recorder.journal.completions_for(
                        consumed
                    ):
                        recorder._restore_completion(preserved)
                    return recorder._response_from_completion(
                        completion,
                        request,
                    )
            host = str(urlsplit(requested_url).hostname)
            if urlsplit(requested_url).query:
                initial_addresses = _public_transport_url(requested_url)
            else:
                initial_addresses = _public_url(requested_url)
            started_at = datetime.now(timezone.utc).isoformat()
            receipt = recorder.access_controller.before_request(requested_url)
            if urlsplit(requested_url).query:
                addresses = _public_transport_url(requested_url)
            else:
                addresses = _public_url(requested_url)
            if addresses != initial_addresses:
                raise ValueError(
                    "transport DNS changed between initial validation and send"
                )
            required_interval = float(receipt.crawl_delay_seconds)
            with recorder._send_lock:
                prior_send_ns = recorder._last_actual_send_ns.get(host)
                top_up_seconds = 0.0
                if prior_send_ns is not None:
                    while True:
                        current_ns = recorder.clock_ns()
                        remaining = (
                            required_interval
                            - (current_ns - prior_send_ns) / 1_000_000_000
                        )
                        if remaining <= 0:
                            break
                        recorder.sleeper(remaining)
                        advanced_ns = recorder.clock_ns()
                        if advanced_ns <= current_ns:
                            raise RuntimeError(
                                "immediate-send rate clock did not advance"
                            )
                        top_up_seconds += remaining
                    if top_up_seconds > 0:
                        if urlsplit(requested_url).query:
                            final_addresses = _public_transport_url(requested_url)
                        else:
                            final_addresses = _public_url(requested_url)
                        if final_addresses != initial_addresses:
                            raise ValueError(
                                "transport DNS changed after immediate-send rate top-up"
                            )
                        addresses = final_addresses
                sent_monotonic_ns = recorder.clock_ns()
                if (
                    prior_send_ns is not None
                    and sent_monotonic_ns - prior_send_ns
                    < int(required_interval * 1_000_000_000)
                ):
                    raise RuntimeError(
                        "immediate-send rate interval remains below policy"
                    )
                recorder._last_actual_send_ns[host] = sent_monotonic_ns
                send_sequence = (
                    max(
                        (
                            int(row["send_sequence"])
                            for row in recorder.send_events
                        ),
                        default=-1,
                    )
                    + 1
                )
                journal_request_sequence = (
                    recorder.journal.start_request(
                        "content",
                        requested_url,
                        requested_at=datetime.now(
                            timezone.utc
                        ).isoformat(),
                    )
                    if recorder.journal is not None
                    else None
                )
                event: dict[str, Any] = {
                    "send_sequence": send_sequence,
                    "host": host,
                    "requested_url": requested_url,
                    "initial_dns_addresses": list(initial_addresses),
                    "post_controller_dns_addresses": list(addresses),
                    "validated_dns_addresses": list(addresses),
                    "validation_started_at": started_at,
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                    "sent_monotonic_ns": sent_monotonic_ns,
                    "required_interval_seconds": required_interval,
                    "immediate_send_top_up_seconds": top_up_seconds,
                    "outcome": "pending",
                }
                recorder.send_events.append(event)
                recorder._send_context_by_url[requested_url] = {
                    "send_sequence": send_sequence,
                    "dns_addresses": addresses,
                    "access_receipt": receipt,
                    "journal_request_sequence": journal_request_sequence,
                }
            request.headers["User-Agent"] = USER_AGENT
            try:
                response = original(session, request, **kwargs)
            except Exception as exc:
                event["outcome"] = "transport_error"
                event["error_type"] = type(exc).__name__
                event["observed_at"] = datetime.now(timezone.utc).isoformat()
                if (
                    recorder.journal is not None
                    and journal_request_sequence is not None
                ):
                    recorder.journal.preserve_failure(
                        journal_request_sequence,
                        observed_at=event["observed_at"],
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                    )
                raise
            observed_at = datetime.now(timezone.utc).isoformat()
            body = bytes(response.content)
            body_digest = hashlib.sha256(body).hexdigest()
            published_at, updated_at, publisher_evidence = (
                extract_publisher_timestamps(body)
            )
            event.update({
                "outcome": "response",
                "final_url": str(response.url),
                "status": int(response.status_code),
                "byte_count": len(body),
                "sha256": body_digest,
                "raw_response": (
                    f"{body_digest[:2]}/{body_digest}.response"
                ),
                "observed_at": observed_at,
                "published_at": published_at,
                "updated_at": updated_at,
                "publisher_time": updated_at or published_at,
                "publisher_date_evidence": publisher_evidence,
            })
            added, consumed_journal_sequences = recorder.record(
                response,
                observed_at,
                access_receipt=receipt,
                send_sequence=send_sequence,
                dns_addresses=addresses,
                journal_request_sequence=journal_request_sequence,
            )
            if (
                recorder.journal is not None
                and journal_request_sequence is not None
            ):
                raw_files_by_path: dict[str, dict[str, Any]] = {}
                chain = [*response.history, response]
                response_chain: list[dict[str, Any]] = []
                for item, record in zip(chain, added, strict=True):
                    raw_row = {
                        "path": record["raw_response"],
                        "byte_count": record["byte_count"],
                        "sha256": record["sha256"],
                    }
                    raw_files_by_path[raw_row["path"]] = raw_row
                    response_chain.append({
                        "method": str(
                            getattr(item.request, "method", "GET")
                        ),
                        "requested_url": record["requested_url"],
                        "response_url": record["response_url"],
                        "status": record["status"],
                        "headers": dict(item.headers),
                        "raw_response": record["raw_response"],
                        "sha256": record["sha256"],
                    })
                recorder.journal.preserve_response(
                    journal_request_sequence,
                    status=int(response.status_code),
                    observed_at=observed_at,
                    final_url=str(response.url),
                    raw_files=[
                        raw_files_by_path[path]
                        for path in sorted(raw_files_by_path)
                    ],
                    replay_payload={
                        "send_event": dict(event),
                        "raw_response_records": [
                            dict(row) for row in added
                        ],
                        "response_chain": response_chain,
                    },
                    consumed_request_sequences=(
                        consumed_journal_sequences
                        or [journal_request_sequence]
                    ),
                )
            return response

        requests.sessions.Session.send = send
        try:
            yield
        finally:
            requests.sessions.Session.send = original


class AuditedRobotsClient:
    """Preserve every robots response before the policy decides its meaning."""

    def __init__(
        self,
        client: Any,
        cache: RawResponseCache,
        *,
        journal: DurableRequestJournal | None = None,
    ) -> None:
        self.client = client
        self.cache = cache
        self.journal = journal
        self.events: list[dict[str, Any]] = []

    def fetch(self, engine: str, url: str, **kwargs: Any) -> dict[str, Any]:
        if self.journal is not None:
            completion = self.journal.replay("robots", url)
            if completion is not None:
                payload = completion.get("replay_payload")
                if not isinstance(payload, dict):
                    raise RuntimeError(
                        "journal robots replay payload is invalid"
                    )
                event = payload.get("audit_event")
                metadata = payload.get("response")
                if not isinstance(event, dict) or not isinstance(
                    metadata,
                    dict,
                ):
                    raise RuntimeError(
                        "journal robots replay evidence is invalid"
                    )
                reference = str(event.get("raw_response", ""))
                digest = str(event.get("sha256", ""))
                body = self.cache.resolve(reference, digest)
                restored = dict(metadata)
                restored["body_base64"] = base64.b64encode(
                    body
                ).decode("ascii")
                restored["body_bytes"] = len(body)
                self.events.append(dict(event))
                return restored
        addresses = _public_url(url)
        requested_at = datetime.now(timezone.utc).isoformat()
        requested_monotonic_ns = time.monotonic_ns()
        journal_request_sequence = (
            self.journal.start_request(
                "robots",
                url,
                requested_at=requested_at,
            )
            if self.journal is not None
            else None
        )
        try:
            response = self.client.fetch(engine, url, **kwargs)
        except Exception as exc:
            observed_at = datetime.now(timezone.utc).isoformat()
            self.events.append({
                "host": urlsplit(url).hostname,
                "requested_url": url,
                "validated_dns_addresses": list(addresses),
                "requested_at": requested_at,
                "requested_monotonic_ns": requested_monotonic_ns,
                "observed_at": observed_at,
                "decision": "unavailable",
                "reason": type(exc).__name__,
            })
            if (
                self.journal is not None
                and journal_request_sequence is not None
            ):
                self.journal.preserve_failure(
                    journal_request_sequence,
                    observed_at=observed_at,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            raise
        try:
            body = base64.b64decode(
                str(response["body_base64"]),
                validate=True,
            )
            if len(body) != int(response.get("body_bytes", -1)):
                raise ValueError("robots response byte count mismatch")
        except (KeyError, ValueError) as exc:
            self.events.append({
                "host": urlsplit(url).hostname,
                "requested_url": url,
                "validated_dns_addresses": list(addresses),
                "requested_at": requested_at,
                "requested_monotonic_ns": requested_monotonic_ns,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "decision": "unavailable",
                "reason": type(exc).__name__,
            })
            raise
        digest, reference = self.cache.store(body)
        history = [
            {
                "url": str(item.get("url", "")),
                "status": int(item.get("status", 0)),
            }
            for item in response.get("history", ()) or ()
        ]
        event = {
            "host": urlsplit(url).hostname,
            "requested_url": url,
            "final_url": str(response.get("url", url)),
            "validated_dns_addresses": list(addresses),
            "requested_at": requested_at,
            "requested_monotonic_ns": requested_monotonic_ns,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "status": int(response.get("status", 0)),
            "byte_count": len(body),
            "sha256": digest,
            "raw_response": reference,
            "redirect_history": history,
            "decision": "pending",
            "reason": "awaiting_public_access_decision",
        }
        self.events.append(event)
        if (
            self.journal is not None
            and journal_request_sequence is not None
        ):
            target = (self.cache.root / reference).resolve()
            relative = target.relative_to(self.cache.root.resolve()).as_posix()
            self.journal.preserve_response(
                journal_request_sequence,
                status=int(response.get("status", 0)),
                observed_at=str(event["observed_at"]),
                final_url=str(response.get("url", url)),
                raw_files=[{
                    "path": relative,
                    "byte_count": len(body),
                    "sha256": digest,
                }],
                replay_payload={
                    "audit_event": dict(event),
                    "response": {
                        "url": str(response.get("url", url)),
                        "status": int(response.get("status", 0)),
                        "history": history,
                        "text": str(response.get("text", "")),
                    },
                },
            )
        return response

    def mark_decision(self, content_url: str, *, allowed: bool, reason: str) -> None:
        host = urlsplit(content_url).hostname
        for event in reversed(self.events):
            if event.get("host") == host and event.get("decision") == "pending":
                event["decision"] = "allowed" if allowed else "denied"
                event["reason"] = reason
                event["content_route"] = content_url
                return


class AuditedAccessController:
    """Bind the public-access decision to the exact audited robots response."""

    def __init__(
        self,
        controller: PublicAccessController,
        robots_client: AuditedRobotsClient,
    ) -> None:
        self.controller = controller
        self.robots_client = robots_client
        self.policy = controller.policy

    @property
    def receipts(self) -> tuple[Any, ...]:
        return self.controller.receipts

    @property
    def robots_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self.robots_client.events)

    def before_request(self, url: str) -> Any:
        try:
            receipt = self.controller.before_request(url)
        except Exception as exc:
            self.robots_client.mark_decision(
                url,
                allowed=False,
                reason=str(exc),
            )
            raise
        self.robots_client.mark_decision(
            url,
            allowed=True,
            reason="public_access_allowed",
        )
        return receipt

    def authorize_replay(self, url: str) -> Any:
        """Revalidate terms and robots without reserving a nonexistent send."""
        try:
            receipt = self.controller.authorize(url)
        except Exception as exc:
            self.robots_client.mark_decision(
                url,
                allowed=False,
                reason=str(exc),
            )
            raise
        self.robots_client.mark_decision(
            url,
            allowed=True,
            reason="public_access_allowed",
        )
        return receipt


def _field(payload: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        value = payload.get(name)
        if value not in (None, "", [], {}):
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
    return ""


def _vacancy(raw: Any, posted_at: str | None, config: dict[str, Any] | None = None) -> Vacancy:
    payload = raw.raw_json if isinstance(raw.raw_json, dict) else {}
    body = _field(payload, ("content_text", "descriptionPlain", "description",
                            "jobDescription", "contents", "text", "requirements"))
    token = str(raw.job_id).split(":", 1)[0]
    companies = (config or {}).get("companies") or {}
    configured_company = companies.get(token, "") if isinstance(companies, dict) else token
    return Vacancy(
        key=raw.key, board=raw.board, job_id=raw.job_id, url=raw.url,
        posted_at=str(posted_at or _field(payload, ("datePosted", "postedAt", "published_at", "createdAt"))),
        raw_text=str(raw.raw_text or ""), raw_json=payload,
        title=_field(payload, ("title", "job_title", "jobTitle", "name", "position", "text")),
        company=_field(payload, ("company", "companyName", "employerName", "organization")) or str(configured_company),
        location=_field(payload, ("location_text", "location", "locations", "jobLocation", "city", "country", "workplace")),
        body=body or str(raw.raw_text or ""),
        expiry=_field(payload, ("expiryDate", "expires_at", "expirationDate", "validThrough", "deadline")),
    )


def _opportunity(vacancy: Vacancy) -> tuple[Opportunity0Input, Confidence]:
    """Deterministic, candidate-independent extraction from official content."""
    text = f"{vacancy.title}\n{vacancy.body}".casefold()
    market = 8500 if re.search(r"\b(ai|machine learning|software|data|security|platform|cloud)\b", text) else 6500
    quality = 8000
    if re.search(r"\b(unpaid|volunteer|zero[- ]hours)\b", text):
        quality = 2500
    elif re.search(r"\b(fixed[- ]term|temporary|internship|contract)\b", text):
        quality = 6000
    accessibility = 9000
    complete = bool(vacancy.title and vacancy.company and vacancy.location and len(vacancy.body) >= 120)
    confidence = 9000 if complete else 6500
    return (Opportunity0Input(market, quality, accessibility),
            Confidence(confidence, confidence, confidence, confidence))


def _validate_config(payload: Any) -> tuple[list[str], dict[str, dict[str, Any]], list[str]]:
    if not isinstance(payload, dict):
        raise ValueError("configuration must be an object")
    if "official_sources" in payload:
        raise ValueError(
            "official_sources is retired; configure boards.enabled and top-level board sections"
        )
    boards = payload.get("boards")
    if not isinstance(boards, dict):
        raise ValueError("configuration requires a boards mapping")
    enabled = boards.get("enabled")
    if (not isinstance(enabled, list) or not enabled
            or any(not isinstance(name, str) or not name.strip() for name in enabled)):
        raise ValueError("boards.enabled must be a non-empty list of board names")
    # The collector legitimately enables aggregators and public discovery
    # boards. JAA-04 authority acquisition projects the official ATS subset
    # from that same list; it never turns the other entries into authorities.
    names = sorted(set(enabled) & OFFICIAL_ADAPTERS)
    if not names:
        raise ValueError("boards.enabled contains no supported official adapters")
    configs: dict[str, dict[str, Any]] = {}
    for name in names:
        section = payload.get(name)
        if section is None:
            section = {}
        if not isinstance(section, dict):
            raise ValueError(f"{name} configuration must be a mapping")
        configs[name] = dict(section)
    terms = payload.get("search_terms")
    if not isinstance(terms, list) or not terms:
        raise ValueError("search_terms must be a non-empty list")
    if any(not isinstance(term, str) or not term.strip() for term in terms):
        raise ValueError("search_terms entries must be non-empty strings")
    return names, configs, list(terms)


def _temporal_admission(refs: list[dict[str, Any]], raw_root: Path,
                        as_of: datetime) -> dict[str, Any]:
    """Replay the downstream ROLE/HIRING publisher-time prerequisite.

    Only a final, successful detail response can supply the publisher time.
    The response receipt time is deliberately recorded but never considered as
    a fallback for absent or invalid publisher metadata.
    """
    finals = [ref for ref in refs if ref.get("status") == 200
              and ref.get("response_url") == ref.get("final_url")]
    response = finals[-1] if finals else None
    response_hash = response.get("sha256") if response else None
    published_at: str | None = None
    updated_at: str | None = None
    publisher_date_evidence: str | None = None
    publisher_time: str | None = None
    reason = "publisher_time_missing_or_malformed"
    if response is not None:
        relative = Path(str(response.get("raw_response", "")))
        path = (raw_root / relative).resolve()
        try:
            if raw_root.resolve() not in path.parents or not path.is_file():
                raise ValueError("detail response bytes are unavailable")
            body = path.read_bytes()
            if hashlib.sha256(body).hexdigest() != response_hash:
                raise ValueError("detail response hash differs from captured bytes")
            published_at, updated_at, publisher_date_evidence = extract_publisher_timestamps(body)
            publisher_time = updated_at or published_at
        except (OSError, UnicodeDecodeError, ValueError, TypeError):
            publisher_time = None
    admitted = False
    if publisher_time is not None:
        try:
            publisher = datetime.fromisoformat(publisher_time.replace("Z", "+00:00"))
            if publisher.tzinfo is None:
                raise ValueError("publisher time has no timezone")
            publisher = publisher.astimezone(timezone.utc)
            publisher_time = publisher.isoformat()
            if publisher > as_of:
                reason = "publisher_time_in_future"
            elif as_of - publisher > timedelta(days=VACANCY_FRESHNESS_DAYS):
                reason = "publisher_time_stale"
            else:
                admitted, reason = True, "publisher_time_current"
        except (TypeError, ValueError, OverflowError):
            publisher_time = None
            reason = "publisher_time_missing_or_malformed"
    return {
        "admitted": admitted,
        "reason": reason,
        "publisher_time": publisher_time,
        "published_at": published_at,
        "updated_at": updated_at,
        "publisher_date_evidence": publisher_date_evidence,
        "temporal_semantics": "publisher_time",
        "as_of": as_of.isoformat(),
        "as_of_date": as_of.date().isoformat(),
        "freshness_days": VACANCY_FRESHNESS_DAYS,
        "authority_response_sha256": response_hash,
    }


def _raw_inventory(raw_root: Path) -> tuple[list[dict[str, Any]], str]:
    inventory: list[dict[str, Any]] = []
    for path in sorted(
        (item for item in raw_root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(raw_root).as_posix(),
    ):
        body = path.read_bytes()
        inventory.append({
            "path": path.relative_to(raw_root).as_posix(),
            "byte_count": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        })
    return inventory, hashlib.sha256(_canonical(inventory)).hexdigest()


def _select_candidates(
    candidates: list[dict[str, Any]],
    quarantine_index: QuarantineIndex,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    seen_identity: set[str] = set()
    seen_url: set[str] = set()
    seen_body: set[str] = set()
    for ordinal, candidate in enumerate(candidates, start=1):
        identity = candidate["job_key"]
        url = _normal_url(candidate["url"])
        body_hash = candidate["content_sha256"]
        payload_hash = candidate["payload_hash"]
        duplicate_reason: str | None = None
        if identity in quarantine_index.job_keys:
            duplicate_reason = "quarantined_job_key"
        elif payload_hash in quarantine_index.payload_hashes:
            duplicate_reason = "quarantined_payload_hash"
        elif identity in seen_identity:
            duplicate_reason = "duplicate_identity"
        elif url in seen_url:
            duplicate_reason = "duplicate_url"
        elif body_hash in seen_body:
            duplicate_reason = "duplicate_content"
        if duplicate_reason is None:
            seen_identity.add(identity)
            seen_url.add(url)
            seen_body.add(body_hash)
            if len(records) < COHORT_SIZE:
                records.append(candidate)
                disposition = "selected"
            else:
                disposition = "below_exact_30_cut"
        else:
            disposition = duplicate_reason
        trace.append({
            "ordinal": ordinal,
            "job_key": identity,
            "score_bp": candidate["opportunity0_decision"]["score_bp"],
            "canonical_url": url,
            "content_sha256": body_hash,
            "payload_hash": payload_hash,
            "publisher_time": candidate["temporal_admission"]["publisher_time"],
            "official_response_hashes": sorted({
                ref["sha256"] for ref in candidate["raw_response_refs"]
            }),
            "disposition": disposition,
            "quarantine_index_sha256": quarantine_index.sha256,
        })
    return records, trace


def _timing_evidence(
    sends: list[dict[str, Any]],
    robots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    first_robot_by_host = {
        str(row.get("host")): int(row["requested_monotonic_ns"])
        for row in robots
        if isinstance(row.get("requested_monotonic_ns"), int)
    }
    previous_by_host: dict[str, int] = {}
    result: list[dict[str, Any]] = []
    for send in sends:
        host = str(send.get("host"))
        sent = int(send["sent_monotonic_ns"])
        previous = previous_by_host.get(host, first_robot_by_host.get(host))
        elapsed = None if previous is None else (sent - previous) / 1_000_000_000
        required = float(send["required_interval_seconds"])
        result.append({
            "send_sequence": send["send_sequence"],
            "host": host,
            "sent_at": send["sent_at"],
            "prior_event": (
                "none" if previous is None
                else ("content" if host in previous_by_host else "robots")
            ),
            "elapsed_seconds": elapsed,
            "required_interval_seconds": required,
            "compliant": elapsed is not None and elapsed + 1e-6 >= required,
        })
        previous_by_host[host] = sent
    return result


def _write_run_evidence(
    path: Path,
    *,
    config_path: Path,
    raw_root: Path,
    access_controller: Any,
    recorder: ResponseRecorder,
    selection_trace: list[dict[str, Any]],
    temporal_decisions: list[dict[str, Any]],
    errors: list[str],
    selected_count: int,
    journal: DurableRequestJournal,
    quarantine_index: QuarantineIndex,
) -> dict[str, Any]:
    if path.exists() or path.is_symlink():
        raise RuntimeError("capture evidence output already exists")
    robots = [
        dict(row)
        for row in getattr(access_controller, "robots_events", ())
    ]
    timing = _timing_evidence(recorder.send_events, robots)
    inventory, inventory_hash = _raw_inventory(raw_root)
    observations = [
        str(row[field])
        for rows in (recorder.send_events, robots)
        for row in rows
        for field in ("requested_at", "sent_at", "observed_at")
        if row.get(field)
    ]
    result_status = "admission_floor_satisfied" if selected_count == COHORT_SIZE else (
        "rejected_below_admission_floor"
    )
    payload = {
        "schema_version": "jaa04.official-capture-evidence.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result_status": result_status,
        "selected_count": selected_count,
        "required_count": COHORT_SIZE,
        "configuration": {
            "path": str(config_path),
            "sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        },
        "access_policy": {
            "path": str(access_controller.policy.source_path),
            "sha256": access_controller.policy.policy_sha256,
        },
        "failed_holdout_quarantine": quarantine_index.binding(),
        "raw_store": {
            "root": str(raw_root),
            "inventory": inventory,
            "inventory_sha256": inventory_hash,
        },
        "request_journal": journal.evidence(),
        "observation_window": {
            "first": min(observations) if observations else None,
            "last": max(observations) if observations else None,
        },
        "robots_evidence": robots,
        "content_send_manifest": recorder.send_events,
        "raw_response_index": recorder.records,
        "per_host_timing": timing,
        "selection_trace": selection_trace,
        "selection_trace_sha256": hashlib.sha256(
            _canonical(selection_trace)
        ).hexdigest(),
        "temporal_decisions": temporal_decisions,
        "errors": errors,
    }
    payload["evidence_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    _atomic_write(path, _canonical(payload) + b"\n")
    return payload


def build(
    config_path: Path,
    output: Path,
    raw_root: Path,
    *,
    quarantine_index: QuarantineIndex,
    access_controller: Any | None = None,
    evidence_output: Path | None = None,
    resume: bool = False,
    source_head: str | None = None,
) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError("output snapshot already exists")
    if evidence_output is not None and (
        evidence_output.exists() or evidence_output.is_symlink()
    ):
        raise RuntimeError("capture evidence output already exists")
    if access_controller is None:
        raise RuntimeError("official cohort acquisition requires public access authority")
    policy_sha256 = str(access_controller.policy.policy_sha256)
    journal = DurableRequestJournal.open(
        config_path=config_path,
        policy_sha256=policy_sha256,
        quarantine_index_sha256=quarantine_index.sha256,
        source_head=source_head or source_git_revision(
            Path(__file__).resolve().parents[1]
        ),
        raw_root=raw_root,
        resume=resume,
    )
    robots_client = getattr(access_controller, "robots_client", None)
    if isinstance(robots_client, AuditedRobotsClient):
        robots_client.journal = journal
    boards, configs, terms = _validate_config(load_config(config_path))
    recorder = ResponseRecorder(
        raw_root,
        access_controller,
        journal=journal,
    )
    candidates: list[dict[str, Any]] = []
    temporal_decisions: list[dict[str, Any]] = []
    errors: list[str] = []
    policy = CalibrationPolicy()
    as_of = datetime.now(timezone.utc)
    with recorder.installed():
        for board in boards:
            adapter = load_adapter(board, config=configs[board])
            discovery_start = len(recorder.records)
            try:
                discovered = list(adapter.discover(terms, live=True))
            except Exception as exc:
                errors.append(f"{board}: discovery failed: {exc}")
                continue
            discovery_refs = recorder.records[discovery_start:]
            for job in sorted(discovered, key=lambda row: (row.job_id, row.url)):
                detail_start = len(recorder.records)
                try:
                    raw = adapter.fetch(job, live=True)
                    vacancy = _vacancy(raw, job.posted_at, configs[board])
                    decision = local_decision(vacancy)
                except Exception as exc:
                    errors.append(f"{job.key}: detail failed: {exc}")
                    continue
                detail_refs = recorder.records[detail_start:]
                refs = [*discovery_refs, *detail_refs]
                if not refs or refs[-1]["status"] != 200:
                    continue
                inputs, confidence = _opportunity(vacancy)
                opportunity = decide_opportunity0(
                    inputs, confidence,
                    viability_reason="viable" if decision.reason == "viable" else (
                        decision.reason if decision.reason in {"expired", "inaccessible", "ineligible", "implausibly_senior"}
                        else "ineligible"),
                    policy=policy,
                )
                if decision.decision != "include" or opportunity.decision != "pass":
                    continue
                identity = f"{board}:{job.job_id}"
                temporal = _temporal_admission(detail_refs, raw_root, as_of)
                temporal_decisions.append({"job_key": identity, **temporal})
                if not temporal["admitted"]:
                    continue
                url = _normal_url(vacancy.url)
                body_hash = hashlib.sha256(vacancy.body.encode("utf-8")).hexdigest()
                official_hashes = sorted({ref["sha256"] for ref in refs})
                payload_hash = hashlib.sha256(_canonical({
                    "source_identity": identity, "official_response_hashes": official_hashes,
                    "vacancy": asdict(vacancy),
                })).hexdigest()
                candidates.append({
                    "job_key": identity, "board": board, "company": vacancy.company,
                    "title": vacancy.title, "url": vacancy.url, "payload_hash": payload_hash,
                    "canonical_vacancy_key": canonical_key(vacancy), "content_sha256": body_hash,
                    "observed_at": refs[-1]["observed_at"],
                    "source": {"identity": identity, "adapter": board, "authority": "official-public-employer-or-ats"},
                    "raw_response_refs": refs,
                    "payload": asdict(vacancy),
                    "viability_decision": asdict(decision),
                    "opportunity0_input": asdict(inputs), "confidence": asdict(confidence),
                    "opportunity0_decision": asdict(opportunity),
                    "temporal_admission": temporal,
                })
    candidates.sort(key=lambda row: (-row["opportunity0_decision"]["score_bp"], row["job_key"]))
    records, selection_trace = _select_candidates(candidates, quarantine_index)
    temporal_decisions.sort(key=lambda row: (row["job_key"], str(row["authority_response_sha256"])))
    journal.assert_replay_consumed()
    if evidence_output is not None:
        _write_run_evidence(
            evidence_output,
            config_path=config_path,
            raw_root=raw_root,
            access_controller=access_controller,
            recorder=recorder,
            selection_trace=selection_trace,
            temporal_decisions=temporal_decisions,
            errors=errors,
            selected_count=len(records),
            journal=journal,
            quarantine_index=quarantine_index,
        )
    if len(records) < COHORT_SIZE:
        raise RuntimeError(f"only {len(records)} current unique official vacancies survived; need exactly 30; "
                           + "; ".join(errors[:10]))
    envelope = {
        "schema_version": "jaa04.official-admitted-queue.v2",
        "created_at": as_of.isoformat(),
        "selection": "highest Opportunity-0 score then vacancy identity; exact 30",
        "policy": {"identity": DECISION_RULE_VERSION, "hash": policy.policy_hash,
                   "parameters": calibration_policy_json(policy)},
        "raw_store": {"layout": "sha256-prefix/content-sha256.response",
                      "root": str(raw_root)},
        "temporal_policy": {
            "purposes": [IntelligenceKind.ROLE.value, IntelligenceKind.HIRING.value],
            "temporal_semantics": "publisher_time", "as_of": as_of.isoformat(),
            "as_of_date": as_of.date().isoformat(),
            "freshness_days": VACANCY_FRESHNESS_DAYS,
        },
        "temporal_decisions": temporal_decisions,
        "temporal_decisions_hash": hashlib.sha256(_canonical(temporal_decisions)).hexdigest(),
        "records": records,
        "records_hash": hashlib.sha256(_canonical(records)).hexdigest(),
        "failed_holdout_quarantine": quarantine_index.binding(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(output, _canonical(envelope) + b"\n")
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True,
                        help="external runtime directory for exact official response bytes")
    parser.add_argument("--evidence-output", type=Path, required=True,
                        help="external immutable all-capture evidence manifest")
    parser.add_argument("--access-policy", type=Path, required=True,
                        help="external human terms-review attestations")
    parser.add_argument(
        "--quarantine-index",
        type=Path,
        required=True,
        help="decision-free failed-holdout exclusion index",
    )
    parser.add_argument(
        "--quarantine-index-sha256",
        required=True,
        help="expected SHA-256 of the exact quarantine index bytes",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume only after validating the durable request journal",
    )
    args = parser.parse_args()
    try:
        quarantine_index = load_quarantine_index(
            args.quarantine_index.resolve(),
            args.quarantine_index_sha256,
        )
        raw_root = args.raw_root.resolve()
        policy = PublicAccessPolicy.load(args.access_policy.resolve())
        client = ScraplingClient(Path(__file__).resolve().parents[1], {
            "command_timeout_seconds": 45,
        })
        cache = RawResponseCache(raw_root)
        robots_client = AuditedRobotsClient(client, cache)
        controller = AuditedAccessController(PublicAccessController(
            policy,
            robots_client,
            cache,
        ), robots_client)
        envelope = build(
            args.config.resolve(),
            args.output.resolve(),
            raw_root,
            quarantine_index=quarantine_index,
            access_controller=controller,
            evidence_output=args.evidence_output.resolve(),
            resume=args.resume,
        )
    except Exception as exc:
        print(f"JAA-04 official cohort: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "count": len(envelope["records"]),
                      "records_hash": envelope["records_hash"], "snapshot": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
