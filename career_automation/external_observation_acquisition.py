"""JAA-10 external observation acquirer.

Durable, fail-closed acquisition of at most one robots + one list response from
the operator-attested public ATS host.  All network bytes are reserved before
transfer and preserved verbatim whether successful or failed.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from career_automation.public_access import (
    PublicAccessController,
    PublicAccessDenied,
    PublicAccessPolicy,
    RobotsReceipt,
    USER_AGENT,
    _public_origin,
    replay_access_receipt,
)

RECEIPT_SCHEMA = "jaa10.external-observation-acquisition.v1"
MAX_BODY_BYTES = 2_000_000
ROLLING_WINDOW_SECONDS = 86_400.0
MAX_ROLLING_RESERVATIONS = 60
MIN_HOST_INTERVAL_SECONDS = 30.0
CONTROLLER_DELAY_SECONDS = 30.0
RESERVATION_SCHEMA = "jaa10.external-request-reservation.v1"
LEVER_LIST_ROUTE_CLASS = "lever_public_postings_list.v1"
AUTHORIZED_LEVER_LIST_URL = (
    "https://api.lever.co/v0/postings/lever?limit=1&mode=json&skip=0"
)
ROOT = Path(__file__).resolve().parents[1]

_LEDGER_ENTRY_FIELDS = frozenset({
    "schema", "sequence", "reserved_at_unix", "request",
    "request_sha256", "prev_event_sha256", "event_sha256",
})
_RESERVATION_REQUEST_FIELDS = frozenset({
    "url", "host", "method", "purpose", "effective_kwargs",
})

# Kwargs the controller or module may supply; all others are unknown and rejected.
_ALLOWED_FETCH_KWARGS = frozenset({
    "timeout", "headers",
    "retries", "retry_delay",
    "follow_redirects", "max_redirects",
    "stealthy_headers", "impersonate",
    "http3", "proxy",
})

# Required fixed values; any deviation raises before reservation.
_FIXED_CONSTRAINTS: dict[str, Any] = {
    "stealthy_headers": False,
    "impersonate": None,
    "http3": False,
    "proxy": None,
    "follow_redirects": False,
    "max_redirects": 0,
    "retries": 1,
    "retry_delay": 0,
}

_FIXED_FETCH_KWARGS: dict[str, Any] = {
    "retries": 1,
    "retry_delay": 0,
    "follow_redirects": False,
    "max_redirects": 0,
    "stealthy_headers": False,
    "impersonate": None,
    "http3": False,
    "proxy": None,
}


class ObservationAcquisitionError(RuntimeError):
    """Fail-closed error for any acquisition violation."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _external_path(path: Path, *, label: str) -> Path:
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    raise ObservationAcquisitionError(
        f"{label.upper().replace(' ', '_')}_REJECTED: path must be outside "
        "the product repository"
    )


def _utc_datetime(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ObservationAcquisitionError(
            f"{label}: timestamp must be a timezone-aware datetime"
        )
    return value.astimezone(timezone.utc)


def _validate_content_url(
    url: str,
    *,
    allowed_hosts: frozenset[str] | None = None,
    route_class: str = LEVER_LIST_ROUTE_CLASS,
) -> tuple[str, str, str]:
    """Return (scheme, host, port) after strict content-URL validation.

    Rejects: userinfo, fragment, IP literal (even public), non-default port,
    private/localhost/non-global host.
    """
    parsed = urlsplit(url)
    if parsed.fragment:
        raise ObservationAcquisitionError(
            f"CONTENT_URL_REJECTED: fragment not permitted in {url!r}"
        )
    try:
        scheme, host, port = _public_origin(url)
    except PublicAccessDenied as exc:
        raise ObservationAcquisitionError(
            f"CONTENT_URL_REJECTED: {exc}"
        ) from exc
    if scheme != "https":
        raise ObservationAcquisitionError(
            f"CONTENT_URL_REJECTED: only https scheme permitted, got {scheme!r}"
        )
    if port:
        raise ObservationAcquisitionError(
            f"CONTENT_URL_REJECTED: non-default port not permitted in {url!r}"
        )
    try:
        ipaddress.ip_address(host)
        raise ObservationAcquisitionError(
            f"CONTENT_URL_REJECTED: IP literal not permitted in {url!r}"
        )
    except ValueError:
        pass
    if allowed_hosts is not None:
        if (
            not allowed_hosts
            or any(
                not isinstance(item, str)
                or not item
                or item != item.casefold()
                for item in allowed_hosts
            )
        ):
            raise ObservationAcquisitionError(
                "CONTENT_URL_REJECTED: allowed_hosts must be non-empty "
                "lowercase hostnames"
            )
        if host not in allowed_hosts:
            raise ObservationAcquisitionError(
                f"CONTENT_URL_REJECTED: host {host!r} is outside the allowlist"
            )
    if route_class != LEVER_LIST_ROUTE_CLASS:
        raise ObservationAcquisitionError(
            f"ROUTE_DENIED: unsupported route classification {route_class!r}"
        )
    if url != AUTHORIZED_LEVER_LIST_URL:
        raise ObservationAcquisitionError(
            "ROUTE_DENIED: this increment admits only the exact Lever list route"
        )
    return scheme, host, port


def _revalidate_policy(
    policy: PublicAccessPolicy,
    *,
    url: str,
    at: datetime,
) -> PublicAccessPolicy:
    if not isinstance(policy, PublicAccessPolicy):
        raise ObservationAcquisitionError(
            "POLICY_DENIED: policy must be a PublicAccessPolicy"
        )
    source = policy.source_path
    if source is None:
        raise ObservationAcquisitionError(
            "POLICY_DENIED: policy must retain exact external source bytes"
        )
    source = _external_path(source, label="policy source")
    if source.is_symlink() or not source.is_file():
        raise ObservationAcquisitionError(
            "POLICY_DENIED: policy source must be one external regular file"
        )
    try:
        reloaded = PublicAccessPolicy.load(source, now=at)
        attestation = reloaded.require(url)
    except (OSError, ValueError, PublicAccessDenied) as exc:
        raise ObservationAcquisitionError(f"POLICY_DENIED: {exc}") from exc
    if (
        reloaded.policy_sha256 != policy.policy_sha256
        or reloaded.attestations != policy.attestations
        or attestation.reviewer_type != "human_operator"
        or attestation.determination
        != "public_read_only_research_permitted"
    ):
        raise ObservationAcquisitionError(
            "POLICY_DENIED: in-memory policy differs from exact current source"
        )
    return reloaded


class _SimpleRobotsCache:
    """Minimal in-process cache satisfying PublicAccessController's cache interface."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def store(self, body: bytes) -> tuple[str, str]:
        digest = _sha256_hex(body)
        self._store[digest] = body
        return digest, digest

    def resolve(self, reference: str, digest: str) -> bytes:
        body = self._store.get(reference)
        if body is None or _sha256_hex(body) != digest:
            raise ValueError("robots cache miss or digest mismatch")
        return body


class _LedgeredStaticClient:
    """Private adapter: sole network-capable object given to PublicAccessController.

    Maintains a JSONL reservation ledger (fcntl.flock, hash-chained, mode 0600).
    Every request, including failures, consumes a reservation. Reservations are
    never reversed or deleted.
    """

    def __init__(
        self,
        inner_client: Any,
        ledger_path: Path,
        *,
        wall_clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._inner = inner_client
        self._ledger_path = Path(ledger_path).resolve()
        self._wall_clock: Callable[[], float] = wall_clock if wall_clock is not None else time.time
        self._sleeper: Callable[[float], None] = sleeper if sleeper is not None else time.sleep
        self._issued_reservations: dict[str, dict[str, Any]] = {}
        self._represented_responses: dict[str, dict[str, Any]] = {}

    @property
    def issued_reservations(self) -> Mapping[str, dict[str, Any]]:
        return {
            purpose: dict(entry)
            for purpose, entry in self._issued_reservations.items()
        }

    def represented_response(self, purpose: str) -> dict[str, Any] | None:
        response = self._represented_responses.get(purpose)
        return dict(response) if response is not None else None

    @classmethod
    def _validate_request(cls, value: object, *, line_num: int) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != _RESERVATION_REQUEST_FIELDS:
            raise ObservationAcquisitionError(
                f"LEDGER_CORRUPT: invalid request fields at line {line_num}"
            )
        url = value.get("url")
        host = value.get("host")
        method = value.get("method")
        purpose = value.get("purpose")
        if (
            not isinstance(url, str)
            or not isinstance(host, str)
            or host != host.casefold()
            or method != "GET"
            or purpose not in {"robots", "list"}
            or not isinstance(value.get("effective_kwargs"), dict)
        ):
            raise ObservationAcquisitionError(
                f"LEDGER_CORRUPT: invalid request identity at line {line_num}"
            )
        try:
            scheme, parsed_host, port = _public_origin(url)
        except (PublicAccessDenied, ValueError) as exc:
            raise ObservationAcquisitionError(
                f"LEDGER_CORRUPT: non-public request at line {line_num}"
            ) from exc
        parsed = urlsplit(url)
        if (
            scheme != "https"
            or port
            or parsed.fragment
            or parsed_host != host
            or host != "api.lever.co"
            or (
                purpose == "robots"
                and url != "https://api.lever.co/robots.txt"
            )
            or (purpose == "list" and url != AUTHORIZED_LEVER_LIST_URL)
        ):
            raise ObservationAcquisitionError(
                f"LEDGER_CORRUPT: request route mismatch at line {line_num}"
            )
        try:
            normalized_kwargs = cls._build_fetch_kwargs(
                dict(value["effective_kwargs"])
            )
        except ObservationAcquisitionError as exc:
            raise ObservationAcquisitionError(
                f"LEDGER_CORRUPT: unsafe request kwargs at line {line_num}"
            ) from exc
        if value["effective_kwargs"] != normalized_kwargs:
            raise ObservationAcquisitionError(
                f"LEDGER_CORRUPT: request kwargs differ at line {line_num}"
            )
        return value

    def _read_ledger(self) -> list[dict[str, Any]]:
        """Read and fully verify the JSONL ledger. Caller must hold the lock."""
        path = self._ledger_path
        if not path.exists():
            return []
        if (
            path.is_symlink()
            or not path.is_file()
            or (path.stat().st_mode & 0o777) != 0o600
        ):
            raise ObservationAcquisitionError(
                "LEDGER_CORRUPT: ledger must be one regular mode-0600 file"
            )
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ObservationAcquisitionError(
                "LEDGER_ERROR: cannot read reservation ledger"
            ) from exc
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise ObservationAcquisitionError(
                "LEDGER_CORRUPT: ledger has an unterminated final record"
            )
        entries: list[dict[str, Any]] = []
        prev_hash = "0" * 64
        previous_timestamp: float | None = None
        host_timestamps: dict[str, float] = {}
        lines = raw[:-1].split(b"\n")
        for line_num, line_bytes in enumerate(lines, start=1):
            if not line_bytes:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: blank record at line {line_num}"
                )
            try:
                line_str = line_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: non-UTF-8 at line {line_num}"
                ) from exc
            try:
                entry = json.loads(line_str)
            except json.JSONDecodeError as exc:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: invalid JSON at line {line_num}"
                ) from exc
            if not isinstance(entry, dict):
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: non-object at line {line_num}"
                )
            if set(entry) != _LEDGER_ENTRY_FIELDS:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: wrong fields at line {line_num}: "
                    f"got {sorted(entry)}"
                )
            expected_seq = len(entries) + 1
            if type(entry["sequence"]) is not int or entry["sequence"] != expected_seq:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: sequence gap at line {line_num}"
                )
            if entry["schema"] != RESERVATION_SCHEMA:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: wrong schema at line {line_num}"
                )
            if (
                type(entry["reserved_at_unix"]) not in {int, float}
                or not math.isfinite(float(entry["reserved_at_unix"]))
            ):
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: invalid timestamp at line {line_num}"
                )
            timestamp = float(entry["reserved_at_unix"])
            if previous_timestamp is not None and timestamp < previous_timestamp:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: timestamps moved backwards at line {line_num}"
                )
            request = self._validate_request(entry["request"], line_num=line_num)
            previous_host_timestamp = host_timestamps.get(request["host"])
            if (
                previous_host_timestamp is not None
                and timestamp - previous_host_timestamp
                < MIN_HOST_INTERVAL_SECONDS
            ):
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: host interval violated at line {line_num}"
                )
            expected_request_hash = _sha256_hex(_canonical_json(request))
            if entry["request_sha256"] != expected_request_hash:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: request_sha256 mismatch at line {line_num}"
                )
            if entry["prev_event_sha256"] != prev_hash:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: prev_event_sha256 mismatch at line {line_num}"
                )
            if not _is_sha256(entry["event_sha256"]):
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: malformed event_sha256 at line {line_num}"
                )
            event_payload = {
                k: v for k, v in entry.items() if k != "event_sha256"
            }
            expected_event_hash = _sha256_hex(_canonical_json(event_payload))
            if entry["event_sha256"] != expected_event_hash:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: event_sha256 mismatch at line {line_num}"
                )
            canonical_line = _canonical_json(entry).decode("utf-8")
            if canonical_line != line_str:
                raise ObservationAcquisitionError(
                    f"LEDGER_CORRUPT: non-canonical JSON at line {line_num}"
                )
            entries.append(entry)
            prev_hash = entry["event_sha256"]
            previous_timestamp = timestamp
            host_timestamps[request["host"]] = timestamp
        return entries

    def _check_limits(
        self, entries: list[dict[str, Any]], host: str, now: float
    ) -> float:
        """Return required sleep seconds (0.0 if none). Raises on budget exceeded."""
        if not math.isfinite(now):
            raise ObservationAcquisitionError(
                "LEDGER_ERROR: non-finite wall time"
            )
        if entries:
            latest_ts = entries[-1]["reserved_at_unix"]
            if now < float(latest_ts):
                raise ObservationAcquisitionError(
                    "LEDGER_ERROR: wall clock moved backwards relative to ledger"
                )
        window_start = now - ROLLING_WINDOW_SECONDS
        rolling_count = sum(
            1
            for e in entries
            if float(e["reserved_at_unix"]) > window_start
        )
        if rolling_count >= MAX_ROLLING_RESERVATIONS:
            raise ObservationAcquisitionError(
                f"RATE_DENIED: rolling 24h budget exhausted "
                f"({rolling_count}/{MAX_ROLLING_RESERVATIONS})"
            )
        host_entries = [e for e in entries if e["request"]["host"] == host]
        if host_entries:
            last_ts = float(host_entries[-1]["reserved_at_unix"])
            elapsed = now - last_ts
            remaining = MIN_HOST_INTERVAL_SECONDS - elapsed
            if remaining > 0:
                return remaining
        return 0.0

    def _append_reservation(
        self,
        entries: list[dict[str, Any]],
        request: dict[str, Any],
        now: float,
    ) -> dict[str, Any]:
        """Append one reservation entry and fsync. Caller must hold the lock."""
        prev_hash = entries[-1]["event_sha256"] if entries else "0" * 64
        sequence = len(entries) + 1
        event_payload: dict[str, Any] = {
            "schema": RESERVATION_SCHEMA,
            "sequence": sequence,
            "reserved_at_unix": now,
            "request": request,
            "request_sha256": _sha256_hex(_canonical_json(request)),
            "prev_event_sha256": prev_hash,
        }
        event_hash = _sha256_hex(_canonical_json(event_payload))
        entry: dict[str, Any] = dict(event_payload)
        entry["event_sha256"] = event_hash
        line = _canonical_json(entry) + b"\n"
        path = self._ledger_path
        is_new = not path.exists()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(str(path), flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab", closefd=False) as stream:
                stream.write(line)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        if is_new:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        return entry

    def _reserve_and_delegate(
        self,
        request: dict[str, Any],
        delegate: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        """Lock → verify → enforce limits → sleep-outside-lock if needed →
        re-verify → append reservation → unlock → delegate.  Never reverses."""
        ledger_path = self._ledger_path
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        _fsync_dir(ledger_path.parent)
        lock_path = ledger_path.with_name(ledger_path.name + ".lock")

        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            entries = self._read_ledger()
            now = float(self._wall_clock())
            host = str(request["host"])
            sleep_secs = self._check_limits(entries, host, now)

            if sleep_secs > 0:
                # Sleep outside the lock.
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
                lock_fd = -1
                self._sleeper(sleep_secs)
                # Re-acquire and re-verify.
                lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
                os.fchmod(lock_fd, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                entries = self._read_ledger()
                new_now = float(self._wall_clock())
                if not math.isfinite(new_now):
                    raise ObservationAcquisitionError(
                        "LEDGER_ERROR: non-finite wall time after sleep"
                    )
                if new_now <= now:
                    raise ObservationAcquisitionError(
                        "LEDGER_ERROR: clock did not advance after sleep"
                    )
                now = new_now
                remaining = self._check_limits(entries, host, now)
                if remaining > 0:
                    raise ObservationAcquisitionError(
                        "RATE_DENIED: host interval still not satisfied after sleep"
                    )

            reservation = self._append_reservation(entries, request, now)
            purpose = str(request["purpose"])
            if purpose in self._issued_reservations:
                raise ObservationAcquisitionError(
                    f"RESERVATION_ERROR: duplicate {purpose!r} request in one run"
                )
            self._issued_reservations[purpose] = reservation
        finally:
            if lock_fd != -1:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass
        # Delegate outside lock — reservation is already durable.
        response = delegate()
        if not isinstance(response, dict):
            raise ObservationAcquisitionError(
                "RESPONSE_REJECTED: inner client returned a non-object"
            )
        self._represented_responses[str(request["purpose"])] = dict(response)
        return response

    @staticmethod
    def _build_fetch_kwargs(user_kwargs: dict[str, Any]) -> dict[str, Any]:
        """Validate user_kwargs against allowlist and fixed constraints."""
        unknown = set(user_kwargs) - _ALLOWED_FETCH_KWARGS
        if unknown:
            raise ObservationAcquisitionError(
                f"FETCH_REJECTED: unknown kwargs {sorted(unknown)}"
            )
        for key, required in _FIXED_CONSTRAINTS.items():
            if key not in user_kwargs:
                continue
            caller_val = user_kwargs[key]
            if required is None:
                if caller_val is not None:
                    raise ObservationAcquisitionError(
                        f"FETCH_REJECTED: {key} must be None, got {caller_val!r}"
                    )
            elif isinstance(required, bool):
                if caller_val is not required:
                    raise ObservationAcquisitionError(
                        f"FETCH_REJECTED: {key} must be {required}, got {caller_val!r}"
                    )
            else:
                if type(caller_val) is not type(required) or caller_val != required:
                    raise ObservationAcquisitionError(
                        f"FETCH_REJECTED: {key} must be {required}, "
                        f"got {caller_val!r}"
                    )
        timeout = user_kwargs.get("timeout", CONTROLLER_DELAY_SECONDS)
        if (
            type(timeout) not in {int, float}
            or not math.isfinite(float(timeout))
            or not 0 < float(timeout) <= CONTROLLER_DELAY_SECONDS
        ):
            raise ObservationAcquisitionError(
                "FETCH_REJECTED: timeout must be finite, positive and at most 30"
            )
        supplied_headers = user_kwargs.get("headers", {"User-Agent": USER_AGENT})
        if (
            not isinstance(supplied_headers, Mapping)
            or dict(supplied_headers) != {"User-Agent": USER_AGENT}
        ):
            raise ObservationAcquisitionError(
                "FETCH_REJECTED: headers must contain only the honest User-Agent"
            )
        kwargs: dict[str, Any] = dict(_FIXED_FETCH_KWARGS)
        kwargs["timeout"] = float(timeout)
        kwargs["headers"] = {"User-Agent": USER_AGENT}
        return kwargs

    @staticmethod
    def _request(
        url: str,
        host: str,
        purpose: str,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "url": url,
            "host": host,
            "method": "GET",
            "purpose": purpose,
            "effective_kwargs": kwargs,
        }

    def fetch(self, engine: str, url: str, **user_kwargs: Any) -> dict[str, Any]:
        """Controller-facing fetch: accepts only static engine and /robots.txt path."""
        if engine != "static":
            raise ObservationAcquisitionError(
                f"FETCH_REJECTED: engine must be 'static', got {engine!r}"
            )
        parsed = urlsplit(url)
        if parsed.path != "/robots.txt" or parsed.query or parsed.fragment:
            raise ObservationAcquisitionError(
                f"FETCH_REJECTED: fetch() accepts only /robots.txt, "
                f"got path {parsed.path!r}"
            )
        try:
            scheme, host, port = _public_origin(url)
        except PublicAccessDenied as exc:
            raise ObservationAcquisitionError(
                f"FETCH_REJECTED: robots URL invalid: {exc}"
            ) from exc
        if scheme != "https" or port:
            raise ObservationAcquisitionError(
                "FETCH_REJECTED: robots URL must be public HTTPS on default port"
            )
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ObservationAcquisitionError(
                "FETCH_REJECTED: robots URL must not use an IP literal"
            )
        kwargs = self._build_fetch_kwargs(dict(user_kwargs))
        request = self._request(url, host, "robots", kwargs)

        def _delegate() -> dict[str, Any]:
            return self._inner.fetch("static", url, **kwargs)

        response = self._reserve_and_delegate(request, _delegate)
        _validate_robots_response(response, host, url)
        return response

    def fetch_content(self, url: str, purpose: str) -> dict[str, Any]:
        """Acquire and fetch one content URL. purpose must be 'list' or 'detail'."""
        if purpose not in ("list", "detail"):
            raise ObservationAcquisitionError(
                f"FETCH_REJECTED: purpose must be 'list' or 'detail', "
                f"got {purpose!r}"
            )
        parsed = urlsplit(url)
        if parsed.path == "/robots.txt":
            raise ObservationAcquisitionError(
                "FETCH_REJECTED: fetch_content() rejects /robots.txt"
            )
        _, host, _ = _validate_content_url(url)
        kwargs = self._build_fetch_kwargs({})
        request = self._request(url, host, purpose, kwargs)

        def _delegate() -> dict[str, Any]:
            return self._inner.fetch("static", url, **kwargs)

        return self._reserve_and_delegate(request, _delegate)


def _validate_response(
    response: dict[str, Any],
    expected_host: str,
    request_url: str,
) -> tuple[bytes, str, str, str, int]:
    """Return body and exact represented response/request identities.

    Validates host, status, method, redirect absence, proxy absence,
    base64/byte-count integrity, and post-transfer body ceiling.
    """
    resp_url = str(response.get("url", request_url))
    try:
        _, resp_host, _ = _public_origin(resp_url)
    except PublicAccessDenied as exc:
        raise ObservationAcquisitionError(
            f"RESPONSE_REJECTED: response URL invalid: {exc}"
        ) from exc
    if resp_host != expected_host or resp_url != request_url:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: response URL does not exactly match the request"
        )
    if type(response.get("status")) is not int:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: status must be an integer"
        )
    status = response["status"]
    if status != 200:
        raise ObservationAcquisitionError(
            f"RESPONSE_REJECTED: non-200 status {status}"
        )
    method = response.get("method")
    if method != "GET":
        raise ObservationAcquisitionError(
            f"RESPONSE_REJECTED: method {method!r} is not GET"
        )
    history = response.get("history")
    if not isinstance(history, list) or history:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: unexpected redirect history"
        )
    meta = response.get("meta")
    if not isinstance(meta, dict) or "proxy" not in meta or meta["proxy"] is not None:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: proxy indicated in meta"
        )
    try:
        body = base64.b64decode(str(response["body_base64"]), validate=True)
    except (KeyError, ValueError) as exc:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: body_base64 invalid"
        ) from exc
    declared = response.get("body_bytes")
    if type(declared) is not int or declared != len(body):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: body_bytes mismatch"
        )
    if len(body) > MAX_BODY_BYTES:
        raise ObservationAcquisitionError(
            f"RESPONSE_REJECTED: body {len(body)} bytes exceeds "
            f"post-transfer maximum {MAX_BODY_BYTES}"
        )
    body_sha256 = _sha256_hex(body)
    raw_headers = response.get("headers")
    if not isinstance(raw_headers, dict):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: represented headers must be a mapping"
        )
    casefolded: dict[str, Any] = {}
    for key, value in raw_headers.items():
        folded = str(key).casefold()
        if not folded or folded in casefolded:
            raise ObservationAcquisitionError(
                "RESPONSE_REJECTED: represented header names collide"
            )
        casefolded[folded] = value
    represented_headers_sha256 = _sha256_hex(_canonical_json(casefolded))
    request_headers = response.get("request_headers")
    if not isinstance(request_headers, dict):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: represented request headers must be a mapping"
        )
    folded_request_headers = {
        str(key).casefold(): value for key, value in request_headers.items()
    }
    if (
        len(folded_request_headers) != len(request_headers)
        or folded_request_headers.get("user-agent") != USER_AGENT
        or {
            "referer", "cookie", "authorization", "proxy-authorization"
        }
        & set(folded_request_headers)
    ):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: request headers do not prove honest transport"
        )
    represented_request_headers_sha256 = _sha256_hex(
        _canonical_json(folded_request_headers)
    )
    try:
        parsed_body = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: list body is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(parsed_body, list):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: Lever list body must be a JSON array"
        )
    return (
        body,
        body_sha256,
        represented_headers_sha256,
        represented_request_headers_sha256,
        status,
    )


def _validate_robots_response(
    response: dict[str, Any],
    expected_host: str,
    request_url: str,
) -> tuple[bytes, str]:
    """Validate represented robots transport without interpreting REP policy."""
    resp_url = response.get("url")
    if not isinstance(resp_url, str) or resp_url != request_url:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots response URL differs from the request"
        )
    try:
        scheme, host, port = _public_origin(resp_url)
    except PublicAccessDenied as exc:
        raise ObservationAcquisitionError(
            f"RESPONSE_REJECTED: robots response URL invalid: {exc}"
        ) from exc
    if scheme != "https" or host != expected_host or port:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots response origin differs"
        )
    if type(response.get("status")) is not int:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots status must be an integer"
        )
    if response.get("method") != "GET":
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots method is not GET"
        )
    if not isinstance(response.get("history"), list) or response["history"]:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots redirect history is not empty"
        )
    meta = response.get("meta")
    if not isinstance(meta, dict) or set(meta) != {"proxy"} or meta["proxy"] is not None:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots proxy identity is not absent"
        )
    try:
        body = base64.b64decode(str(response["body_base64"]), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots body_base64 invalid"
        ) from exc
    if type(response.get("body_bytes")) is not int or response["body_bytes"] != len(body):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots body_bytes mismatch"
        )
    if len(body) > MAX_BODY_BYTES:
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots body exceeds post-transfer maximum"
        )
    headers = response.get("headers")
    request_headers = response.get("request_headers")
    if not isinstance(headers, dict) or not isinstance(request_headers, dict):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots represented headers are absent"
        )
    if len({str(key).casefold() for key in headers}) != len(headers):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots represented headers collide"
        )
    folded_request_headers = {
        str(key).casefold(): value for key, value in request_headers.items()
    }
    if (
        len(folded_request_headers) != len(request_headers)
        or folded_request_headers.get("user-agent") != USER_AGENT
        or {"referer", "cookie", "authorization", "proxy-authorization"}
        & set(folded_request_headers)
    ):
        raise ObservationAcquisitionError(
            "RESPONSE_REJECTED: robots request headers are not honest"
        )
    return body, _sha256_hex(body)


def _write_evidence_file(path: Path, content: bytes) -> None:
    """Write content to path with O_EXCL, fsync, then chmod 0444."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
        os.fsync(fd)
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _preserve_represented_response(
    evidence_dir: Path,
    *,
    purpose: str,
    response: dict[str, Any] | None,
    rejected: bool,
    include_body: bool = True,
) -> None:
    if response is None:
        return
    suffix = "rejected" if rejected else "accepted"
    _write_evidence_file(
        evidence_dir / f"{purpose}_response_{suffix}.json",
        _canonical_json(response) + b"\n",
    )
    if not include_body:
        return
    try:
        body = base64.b64decode(str(response["body_base64"]), validate=True)
    except (KeyError, TypeError, ValueError):
        return
    _write_evidence_file(
        evidence_dir / f"raw_{purpose}_{suffix}.bin",
        body,
    )


def _write_error(evidence_dir: Path, *, phase: str, exc: BaseException) -> None:
    err = {"error": type(exc).__name__, "message": str(exc), "phase": phase}
    _write_evidence_file(
        evidence_dir / "error.json",
        _canonical_json(err) + b"\n",
    )
    _fsync_dir(evidence_dir)


def _load_represented_response(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        raise ObservationAcquisitionError(
            f"REPLAY_REJECTED: {path.name} lacks a final newline"
        )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservationAcquisitionError(
            f"REPLAY_REJECTED: {path.name} is not UTF-8 JSON"
        ) from exc
    if (
        not isinstance(value, dict)
        or raw != _canonical_json(value) + b"\n"
    ):
        raise ObservationAcquisitionError(
            f"REPLAY_REJECTED: {path.name} is not canonical"
        )
    return value


def acquire_list_observation(
    content_url: str,
    *,
    policy: PublicAccessPolicy,
    allowed_hosts: frozenset[str],
    route_class: str,
    ledger_path: Path,
    evidence_dir: Path,
    inner_client: Any,
    pre_observation_anchor_sha256: str | None = None,
    wall_clock: Callable[[], float] | None = None,
    sleeper: Callable[[float], None] | None = None,
    now_fn: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Acquire robots + one list observation with durable reservation ledger.

    Validates policy and content URL before ledger creation.  Creates an
    exclusive evidence directory (mode 0700) and writes immutable files
    (mode 0444) for raw bytes, receipt, or error.  Never deletes or reverses
    a consumed reservation.

    Returns the full acquisition receipt dict on success.
    Raises ObservationAcquisitionError on any failure, after writing error.json.
    """
    _now_fn: Callable[[], datetime] = (
        now_fn if now_fn is not None
        else (lambda: datetime.now(timezone.utc))
    )
    policy_check_time = _utc_datetime(
        _now_fn(), label="POLICY_DENIED"
    )
    _validate_content_url(
        content_url,
        allowed_hosts=allowed_hosts,
        route_class=route_class,
    )
    _, content_host, _ = _public_origin(content_url)
    policy = _revalidate_policy(policy, url=content_url, at=policy_check_time)
    if pre_observation_anchor_sha256 is not None and not _is_sha256(
        pre_observation_anchor_sha256
    ):
        raise ObservationAcquisitionError(
            "ANCHOR_REJECTED: pre_observation_anchor_sha256 must be lowercase hex"
        )

    ledger_path = _external_path(ledger_path, label="ledger path")
    evidence_dir = _external_path(evidence_dir, label="evidence directory")
    if ledger_path == evidence_dir or evidence_dir in ledger_path.parents:
        raise ObservationAcquisitionError(
            "LEDGER_PATH_REJECTED: mutable ledger must be outside evidence directory"
        )
    if not callable(getattr(inner_client, "fetch", None)):
        raise ObservationAcquisitionError(
            "CLIENT_REJECTED: inner client must expose fetch"
        )

    try:
        evidence_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise ObservationAcquisitionError(
            f"EVIDENCE_DIR_EXISTS: {evidence_dir}"
        ) from exc
    os.chmod(evidence_dir, 0o700)
    _fsync_dir(evidence_dir.parent)

    ledgered = _LedgeredStaticClient(
        inner_client,
        ledger_path,
        wall_clock=wall_clock,
        sleeper=sleeper,
    )
    cache = _SimpleRobotsCache()
    controller = PublicAccessController(
        policy,
        ledgered,
        cache,
        default_delay_seconds=CONTROLLER_DELAY_SECONDS,
        rate_ledger_path=None,
        now=_now_fn,
    )

    robots_receipt: RobotsReceipt | None = None
    robots_body: bytes | None = None
    content_body: bytes | None = None

    try:
        robots_receipt = controller.authorize(content_url)
        robots_body = cache.resolve(
            robots_receipt.raw_response_ref,
            robots_receipt.content_sha256,
        )
        _write_evidence_file(evidence_dir / "raw_robots.bin", robots_body)
    except Exception as exc:
        _preserve_represented_response(
            evidence_dir,
            purpose="robots",
            response=ledgered.represented_response("robots"),
            rejected=True,
        )
        _write_error(evidence_dir, phase="robots", exc=exc)
        raise ObservationAcquisitionError(f"ROBOTS_FAILED: {exc}") from exc

    try:
        raw_response = ledgered.fetch_content(content_url, "list")
        (
            content_body,
            body_sha256,
            repr_headers_sha256,
            repr_request_headers_sha256,
            status,
        ) = _validate_response(raw_response, content_host, content_url)
        _write_evidence_file(evidence_dir / "raw_content.bin", content_body)
        acquired_at = _utc_datetime(
            _now_fn(), label="RECEIPT_TIME_REJECTED"
        ).isoformat()
    except Exception as exc:
        _preserve_represented_response(
            evidence_dir,
            purpose="content",
            response=ledgered.represented_response("list"),
            rejected=True,
        )
        _write_error(evidence_dir, phase="content", exc=exc)
        if isinstance(exc, ObservationAcquisitionError):
            raise
        raise ObservationAcquisitionError(f"CONTENT_FAILED: {exc}") from exc

    try:
        _preserve_represented_response(
            evidence_dir,
            purpose="robots",
            response=ledgered.represented_response("robots"),
            rejected=False,
            include_body=False,
        )
        _preserve_represented_response(
            evidence_dir,
            purpose="content",
            response=ledgered.represented_response("list"),
            rejected=False,
            include_body=False,
        )
    except Exception as exc:
        _write_error(evidence_dir, phase="evidence", exc=exc)
        raise ObservationAcquisitionError(
            f"EVIDENCE_FAILED: {exc}"
        ) from exc

    effective_kwargs: dict[str, Any] = dict(_FIXED_FETCH_KWARGS)
    effective_kwargs["timeout"] = CONTROLLER_DELAY_SECONDS
    effective_kwargs["headers"] = {"User-Agent": USER_AGENT}

    reservations = ledgered.issued_reservations
    if set(reservations) != {"robots", "list"}:
        raise ObservationAcquisitionError(
            "RESERVATION_ERROR: successful acquisition lacks exact reservations"
        )
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "acquired_at": acquired_at,
        "route_class": route_class,
        "allowed_hosts": sorted(allowed_hosts),
        "request": {
            "url": content_url,
            "method": "GET",
            "purpose": "list",
            "effective_kwargs": effective_kwargs,
        },
        "policy_sha256": policy.policy_sha256,
        "terms_attestation": asdict(policy.attestations[content_host]),
        "robots_binding": asdict(robots_receipt),
        "reservation_binding": {
            "schema": RESERVATION_SCHEMA,
            "robots": reservations["robots"],
            "content": reservations["list"],
            "chain_head_sha256": reservations["list"]["event_sha256"],
        },
        "pre_observation_anchor_sha256": pre_observation_anchor_sha256,
        "response": {
            "status": status,
            "url": str(raw_response.get("url", content_url)),
            "body_bytes": len(content_body),
            "body_sha256": body_sha256,
            "represented_headers_sha256": repr_headers_sha256,
            "represented_request_headers_sha256": (
                repr_request_headers_sha256
            ),
        },
        "certifies_slice": False,
        "submission_authority": False,
        "authenticated_external_time": False,
        "certifies_raw_header_order": False,
        "certifies_duplicate_header_preservation": False,
        "certifies_wire_transfer_cap": False,
        "body_size_enforced_post_transfer": True,
        "redirects_followed": False,
        "transport_impersonation": False,
        "stealth_headers": False,
        "proxy_used": False,
    }
    receipt_bytes = _canonical_json(receipt) + b"\n"
    _write_evidence_file(evidence_dir / "receipt.json", receipt_bytes)
    _fsync_dir(evidence_dir)
    return receipt


def replay_list_observation(
    evidence_dir: Path,
    *,
    policy: PublicAccessPolicy,
) -> dict[str, Any]:
    """Deterministically replay one successful immutable evidence directory."""
    evidence_dir = _external_path(evidence_dir, label="evidence directory")
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: evidence directory must be one real directory"
        )
    if (evidence_dir.stat().st_mode & 0o777) != 0o700:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: evidence directory is not mode 0700"
        )
    expected_names = {
        "raw_robots.bin",
        "raw_content.bin",
        "robots_response_accepted.json",
        "content_response_accepted.json",
        "receipt.json",
    }
    actual_names = {item.name for item in evidence_dir.iterdir()}
    if actual_names != expected_names:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: success evidence has missing or extra files"
        )
    for name in expected_names:
        path = evidence_dir / name
        if path.is_symlink() or not path.is_file():
            raise ObservationAcquisitionError(
                f"REPLAY_REJECTED: {name} is not one regular file"
            )
        if path.stat().st_mode & 0o777 != 0o444:
            raise ObservationAcquisitionError(
                f"REPLAY_REJECTED: {name} is not immutable mode 0444"
            )
    raw_receipt = (evidence_dir / "receipt.json").read_bytes()
    if not raw_receipt.endswith(b"\n"):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: receipt lacks a final newline"
        )
    try:
        receipt = json.loads(raw_receipt)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: receipt is not UTF-8 JSON"
        ) from exc
    if not isinstance(receipt, dict) or raw_receipt != _canonical_json(receipt) + b"\n":
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: receipt is not canonical"
        )
    required = {
        "schema", "acquired_at", "route_class", "allowed_hosts", "request",
        "policy_sha256", "terms_attestation", "robots_binding",
        "reservation_binding", "pre_observation_anchor_sha256", "response",
        "certifies_slice", "submission_authority",
        "authenticated_external_time", "certifies_raw_header_order",
        "certifies_duplicate_header_preservation", "certifies_wire_transfer_cap",
        "body_size_enforced_post_transfer", "redirects_followed",
        "transport_impersonation", "stealth_headers", "proxy_used",
    }
    if set(receipt) != required or receipt.get("schema") != RECEIPT_SCHEMA:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: receipt has an invalid field set or schema"
        )
    limitations = {
        "certifies_slice": False,
        "submission_authority": False,
        "authenticated_external_time": False,
        "certifies_raw_header_order": False,
        "certifies_duplicate_header_preservation": False,
        "certifies_wire_transfer_cap": False,
        "body_size_enforced_post_transfer": True,
        "redirects_followed": False,
        "transport_impersonation": False,
        "stealth_headers": False,
        "proxy_used": False,
    }
    if any(receipt.get(key) is not value for key, value in limitations.items()):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: receipt overstates a limitation"
        )
    request = receipt.get("request")
    if not isinstance(request, dict) or set(request) != {
        "url", "method", "purpose", "effective_kwargs"
    }:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: request binding is malformed"
        )
    url = request["url"]
    allowed_hosts_value = receipt.get("allowed_hosts")
    if (
        not isinstance(allowed_hosts_value, list)
        or not allowed_hosts_value
        or any(not isinstance(item, str) for item in allowed_hosts_value)
        or len(set(allowed_hosts_value)) != len(allowed_hosts_value)
    ):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: host allowlist binding is malformed"
        )
    allowed_hosts = frozenset(allowed_hosts_value)
    _validate_content_url(
        url,
        allowed_hosts=allowed_hosts,
        route_class=receipt.get("route_class"),
    )
    if (
        request["method"] != "GET"
        or request["purpose"] != "list"
        or request["effective_kwargs"]
        != {**_FIXED_FETCH_KWARGS,
            "timeout": CONTROLLER_DELAY_SECONDS,
            "headers": {"User-Agent": USER_AGENT}}
    ):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: request transport binding is not admitted"
        )
    try:
        acquired_at = _utc_datetime(
            datetime.fromisoformat(str(receipt["acquired_at"]).replace("Z", "+00:00")),
            label="REPLAY_REJECTED",
        )
    except ValueError as exc:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: acquired_at is invalid"
        ) from exc
    policy = _revalidate_policy(policy, url=url, at=acquired_at)
    _, host, _ = _public_origin(url)
    if (
        receipt["policy_sha256"] != policy.policy_sha256
        or receipt["terms_attestation"] != asdict(policy.attestations[host])
    ):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: exact policy binding differs"
        )
    robots_body = (evidence_dir / "raw_robots.bin").read_bytes()
    robots_response = _load_represented_response(
        evidence_dir / "robots_response_accepted.json"
    )
    represented_robots_body, _ = _validate_robots_response(
        robots_response, host, f"https://{host}/robots.txt"
    )
    if represented_robots_body != robots_body:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: represented robots bytes differ"
        )
    cache = _SimpleRobotsCache()
    cache.store(robots_body)
    try:
        replay_access_receipt(
            receipt.get("robots_binding"),
            cache,
            content_urls=(url,),
            content_retrieved_at=receipt["acquired_at"],
            policies={policy.policy_sha256: policy},
        )
    except (TypeError, ValueError) as exc:
        raise ObservationAcquisitionError(
            f"REPLAY_REJECTED: robots binding differs: {exc}"
        ) from exc
    content_body = (evidence_dir / "raw_content.bin").read_bytes()
    content_response = _load_represented_response(
        evidence_dir / "content_response_accepted.json"
    )
    (
        represented_content_body,
        represented_body_sha256,
        represented_headers_sha256,
        represented_request_headers_sha256,
        represented_status,
    ) = _validate_response(content_response, host, url)
    if represented_content_body != content_body:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: represented content bytes differ"
        )
    response = receipt.get("response")
    if (
        not isinstance(response, dict)
        or set(response) != {
            "status", "url", "body_bytes", "body_sha256",
            "represented_headers_sha256",
            "represented_request_headers_sha256",
        }
        or response["status"] != represented_status
        or response["url"] != url
        or response["body_bytes"] != len(content_body)
        or response["body_sha256"] != represented_body_sha256
        or response["represented_headers_sha256"]
        != represented_headers_sha256
        or response["represented_request_headers_sha256"]
        != represented_request_headers_sha256
    ):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: content bytes or response identity differ"
        )
    try:
        parsed_body = json.loads(content_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: content is not a JSON array"
        ) from exc
    if not isinstance(parsed_body, list):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: content is not a JSON array"
        )
    binding = receipt.get("reservation_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "schema", "robots", "content", "chain_head_sha256"
    } or binding["schema"] != RESERVATION_SCHEMA:
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: reservation binding is malformed"
        )
    entries = [binding["robots"], binding["content"]]
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict) or set(entry) != _LEDGER_ENTRY_FIELDS:
            raise ObservationAcquisitionError(
                "REPLAY_REJECTED: reservation entry fields differ"
            )
        if (
            entry["schema"] != RESERVATION_SCHEMA
            or type(entry["sequence"]) is not int
            or entry["sequence"] <= 0
            or type(entry["reserved_at_unix"]) not in {int, float}
            or not math.isfinite(float(entry["reserved_at_unix"]))
            or not _is_sha256(entry["request_sha256"])
            or not _is_sha256(entry["prev_event_sha256"])
            or not _is_sha256(entry["event_sha256"])
        ):
            raise ObservationAcquisitionError(
                "REPLAY_REJECTED: reservation entry types differ"
            )
        request_value = _LedgeredStaticClient._validate_request(
            entry["request"], line_num=index
        )
        if entry["request_sha256"] != _sha256_hex(_canonical_json(request_value)):
            raise ObservationAcquisitionError(
                "REPLAY_REJECTED: reservation request hash differs"
            )
        event_payload = {
            key: value for key, value in entry.items() if key != "event_sha256"
        }
        if entry["event_sha256"] != _sha256_hex(_canonical_json(event_payload)):
            raise ObservationAcquisitionError(
                "REPLAY_REJECTED: reservation event hash differs"
            )
    first, second = entries
    if (
        first["request"]["purpose"] != "robots"
        or second["request"]["purpose"] != "list"
        or first["request"]["url"] != f"https://{host}/robots.txt"
        or second["request"]["url"] != url
        or second["sequence"] != first["sequence"] + 1
        or second["prev_event_sha256"] != first["event_sha256"]
        or binding["chain_head_sha256"] != second["event_sha256"]
        or float(second["reserved_at_unix"])
        - float(first["reserved_at_unix"]) < MIN_HOST_INTERVAL_SECONDS
    ):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: reservation ordering or separation differs"
        )
    anchor = receipt.get("pre_observation_anchor_sha256")
    if anchor is not None and not _is_sha256(anchor):
        raise ObservationAcquisitionError(
            "REPLAY_REJECTED: opaque anchor is malformed"
        )
    return receipt
