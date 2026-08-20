"""Positive controls for the JAA-10 external observation acquirer."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from career_automation.external_observation_acquisition import (
    AUTHORIZED_LEVER_LIST_URL,
    LEVER_LIST_ROUTE_CLASS,
    RECEIPT_SCHEMA,
    MAX_ROLLING_RESERVATIONS,
    ROLLING_WINDOW_SECONDS,
    ObservationAcquisitionError,
    _LedgeredStaticClient,
    acquire_list_observation,
    replay_list_observation,
)
from career_automation.observation_route_manifest import (
    REPLACEMENT_RULE,
    ROUTE_MANIFEST_SCHEMA,
    ObservationRouteManifest,
)
from career_automation.public_access import PublicAccessPolicy, policy_records_hash

TEST_HOST = "api.lever.co"
CONTENT_URL = "https://api.lever.co/v0/postings/lever?limit=1&mode=json&skip=0"
TEST_NOW = datetime(2026, 8, 2, 0, 0, 0, tzinfo=timezone.utc)
TEST_REVIEWED_AT = "2026-08-01T12:00:00+00:00"
ROBOTS_BODY = b"User-agent: *\nAllow: /\n"
CONTENT_BODY = b'[{"id":"job1","text":"Software Engineer"}]'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _make_policy(
    tmp_path: Path,
    host: str = TEST_HOST,
    reviewed_at: str = TEST_REVIEWED_AT,
    now: datetime = TEST_NOW,
) -> PublicAccessPolicy:
    records = [{
        "host": host,
        "terms_url": "https://www.lever.co/legal/terms-of-service",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": reviewed_at,
        "reviewed_by": "Test Operator",
        "reviewer_type": "human_operator",
        "notes": "test fixture",
    }]
    path = tmp_path / f"policy-{host.replace('.', '-')}.json"
    path.write_bytes(_canonical_json({
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": policy_records_hash(records),
    }) + b"\n")
    return PublicAccessPolicy.load(path, now=now)


def _make_route_manifest(tmp_path: Path) -> ObservationRouteManifest:
    employers = (
        "lever", "jobgether", "palantir", "spotify", "octoenergy", "firstup",
        "electric-twin", "moneyboxapp", "starcompliance", "kitmanlabs", "gearset",
    )
    document = {
        "schema": ROUTE_MANIFEST_SCHEMA,
        "route_class": LEVER_LIST_ROUTE_CLASS,
        "required_observation_units": 10,
        "minimum_fully_verified_units": 8,
        "minimum_distinct_employers_or_boards": 3,
        "maximum_candidate_attempts": len(employers),
        "replacement_rule": REPLACEMENT_RULE,
        "candidates": [
            {
                "employer_or_board_id": employer,
                "url": (
                    f"https://api.lever.co/v0/postings/{employer}"
                    "?limit=1&mode=json&skip=0"
                ),
            }
            for employer in employers
        ],
    }
    path = tmp_path / "route-manifest.json"
    raw = _canonical_json(document) + b"\n"
    if not path.exists():
        path.write_bytes(raw)
        path.chmod(0o444)
    else:
        assert path.read_bytes() == raw
    return ObservationRouteManifest.load(path, expected_sha256=_sha256(raw))


def _robots_response(host: str = TEST_HOST, body: bytes = ROBOTS_BODY) -> dict[str, Any]:
    return {
        "url": f"https://{host}/robots.txt",
        "status": 200,
        "history": [],
        "body_base64": _b64(body),
        "body_bytes": len(body),
        "headers": {"content-type": "text/plain"},
        "request_headers": {"User-Agent": "JAA-Public-Research"},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "OK",
    }


def _content_response(url: str = CONTENT_URL, body: bytes = CONTENT_BODY) -> dict[str, Any]:
    return {
        "url": url,
        "status": 200,
        "history": [],
        "body_base64": _b64(body),
        "body_bytes": len(body),
        "headers": {"content-type": "application/json"},
        "request_headers": {"User-Agent": "JAA-Public-Research"},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "OK",
    }


class FakeInnerClient:
    """Records calls; returns pre-loaded responses or raises configured exceptions."""

    def __init__(
        self,
        responses: list[Any],
        *,
        on_call: dict[int, Any] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responses = list(responses)
        self._on_call: dict[int, Any] = on_call or {}

    def fetch(self, engine: str, url: str, **kwargs: Any) -> dict[str, Any]:
        idx = len(self.calls)
        self.calls.append({"engine": engine, "url": url, "kwargs": dict(kwargs)})
        if idx in self._on_call:
            self._on_call[idx]()
        resp = self._responses[idx]
        if isinstance(resp, BaseException):
            raise resp
        return resp


def _read_raw_ledger(path: Path) -> list[dict[str, Any]]:
    """Read ledger entries without verification (for assertions only)."""
    if not path.exists():
        return []
    entries = []
    for line in path.read_bytes().split(b"\n"):
        if line.strip():
            entries.append(json.loads(line.decode("utf-8")))
    return entries


def _clock(*timestamps: float):
    """Return a callable that yields each timestamp in sequence."""
    it = iter(timestamps)
    return lambda: next(it)


def _noop_sleeper(seconds: float) -> None:
    pass


def _run_acquire(
    tmp_path: Path,
    inner: FakeInnerClient,
    *,
    wall_clock=None,
    sleeper=None,
    pre_anchor: str | None = None,
    host: str = TEST_HOST,
    content_url: str = CONTENT_URL,
    policy: PublicAccessPolicy | None = None,
    ledger_path: Path | None = None,
    evidence_dir: Path | None = None,
) -> dict[str, Any]:
    if policy is None:
        policy = _make_policy(tmp_path, host=host)
    if ledger_path is None:
        ledger_path = tmp_path / "ledger.jsonl"
    if evidence_dir is None:
        evidence_dir = tmp_path / "evidence"
    if wall_clock is None:
        wall_clock = _clock(1_000_000.0, 1_000_031.0)
    if sleeper is None:
        sleeper = _noop_sleeper
    route_manifest = _make_route_manifest(tmp_path)
    return acquire_list_observation(
        content_url,
        policy=policy,
        allowed_hosts=frozenset({host}),
        route_class=LEVER_LIST_ROUTE_CLASS,
        manifest_path=route_manifest.source_path,
        manifest_sha256=route_manifest.manifest_sha256,
        ledger_path=ledger_path,
        evidence_dir=evidence_dir,
        inner_client=inner,
        pre_observation_anchor_sha256=pre_anchor,
        wall_clock=wall_clock,
        sleeper=sleeper,
        now_fn=lambda: TEST_NOW,
    )


# ---------------------------------------------------------------------------
# Observable order: robots reservation → robots GET → content reservation → content GET
# ---------------------------------------------------------------------------

def test_observable_order(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    call_log: list[str] = []

    def robots_hook() -> None:
        entries = _read_raw_ledger(ledger)
        assert len(entries) == 1, "robots reservation must precede robots GET"
        assert entries[0]["request"]["purpose"] == "robots"
        assert entries[0]["request"]["host"] == TEST_HOST
        call_log.append("robots_GET")

    def content_hook() -> None:
        entries = _read_raw_ledger(ledger)
        assert len(entries) == 2, "content reservation must precede content GET"
        assert entries[0]["request"]["purpose"] == "robots"
        assert entries[1]["request"]["purpose"] == "list"
        assert entries[1]["request"]["host"] == TEST_HOST
        call_log.append("content_GET")

    inner = FakeInnerClient(
        [_robots_response(), _content_response()],
        on_call={0: robots_hook, 1: content_hook},
    )
    _run_acquire(
        tmp_path, inner,
        ledger_path=ledger,
        wall_clock=_clock(1_000_000.0, 1_000_031.0),
    )
    assert call_log == ["robots_GET", "content_GET"]
    assert len(inner.calls) == 2


def test_inner_client_never_called_before_reservation(tmp_path: Path) -> None:
    """Even the very first GET must have its reservation already written."""
    ledger = tmp_path / "ledger.jsonl"
    seen_reservation_before_get: list[bool] = []

    def robots_hook() -> None:
        entries = _read_raw_ledger(ledger)
        seen_reservation_before_get.append(
            len(entries) >= 1
            and entries[0]["request"]["purpose"] == "robots"
        )

    inner = FakeInnerClient(
        [_robots_response(), _content_response()],
        on_call={0: robots_hook},
    )
    _run_acquire(tmp_path, inner, ledger_path=ledger,
                 wall_clock=_clock(1_000_000.0, 1_000_031.0))
    assert seen_reservation_before_get == [True]


# ---------------------------------------------------------------------------
# Receipt schema and fields
# ---------------------------------------------------------------------------

def test_receipt_schema(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    assert receipt["schema"] == RECEIPT_SCHEMA


def test_receipt_limitation_fields(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    assert receipt["certifies_slice"] is False
    assert receipt["submission_authority"] is False
    assert receipt["authenticated_external_time"] is False
    assert receipt["certifies_raw_header_order"] is False
    assert receipt["certifies_duplicate_header_preservation"] is False
    assert receipt["certifies_wire_transfer_cap"] is False
    assert receipt["body_size_enforced_post_transfer"] is True
    assert receipt["redirects_followed"] is False
    assert receipt["transport_impersonation"] is False
    assert receipt["stealth_headers"] is False
    assert receipt["proxy_used"] is False


def test_receipt_request_fields(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    req = receipt["request"]
    assert req["url"] == CONTENT_URL
    assert req["method"] == "GET"
    assert req["purpose"] == "list"
    kw = req["effective_kwargs"]
    assert kw["retries"] == 1
    assert kw["retry_delay"] == 0
    assert kw["follow_redirects"] is False
    assert kw["max_redirects"] == 0
    assert kw["stealthy_headers"] is False
    assert kw["impersonate"] is None
    assert kw["http3"] is False
    assert kw["proxy"] is None
    assert kw["headers"] == {"User-Agent": "JAA-Public-Research"}


def test_receipt_response_fields(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    resp = receipt["response"]
    assert resp["status"] == 200
    assert resp["body_bytes"] == len(CONTENT_BODY)
    assert resp["body_sha256"] == _sha256(CONTENT_BODY)
    assert isinstance(resp["represented_headers_sha256"], str)
    assert len(resp["represented_headers_sha256"]) == 64


def test_receipt_robots_binding(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    binding = receipt["robots_binding"]
    assert binding["host"] == TEST_HOST
    assert binding["robots_url"] == f"https://{TEST_HOST}/robots.txt"
    assert binding["status_code"] == 200
    assert binding["allowed"] is True
    assert binding["user_agent"] == "JAA-Public-Research"


def test_receipt_policy_binding(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    policy = _make_policy(tmp_path)
    receipt = _run_acquire(tmp_path, inner, policy=policy)
    assert receipt["policy_sha256"] == policy.policy_sha256
    att = receipt["terms_attestation"]
    assert att["host"] == TEST_HOST
    assert att["reviewer_type"] == "human_operator"
    assert att["determination"] == "public_read_only_research_permitted"


def test_receipt_pre_observation_anchor_stored_verbatim(tmp_path: Path) -> None:
    anchor = "deadbeef" * 8
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner, pre_anchor=anchor)
    assert receipt["pre_observation_anchor_sha256"] == anchor


def test_receipt_pre_observation_anchor_none_when_absent(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    assert receipt["pre_observation_anchor_sha256"] is None


def test_receipt_meta_proxy_is_none_asserted(tmp_path: Path) -> None:
    """Inner client response must carry meta.proxy=None and receipt does not claim proxy."""
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner)
    assert receipt["proxy_used"] is False


# ---------------------------------------------------------------------------
# Evidence files
# ---------------------------------------------------------------------------

def test_evidence_files_exist(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, evidence_dir=ev)
    assert (ev / "raw_robots.bin").exists()
    assert (ev / "raw_content.bin").exists()
    assert (ev / "robots_response_accepted.json").exists()
    assert (ev / "content_response_accepted.json").exists()
    assert (ev / "receipt.json").exists()
    assert not (ev / "error.json").exists()


def test_evidence_files_mode_0444(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, evidence_dir=ev)
    for name in (
        "raw_robots.bin",
        "raw_content.bin",
        "robots_response_accepted.json",
        "content_response_accepted.json",
        "receipt.json",
    ):
        mode = stat.S_IMODE(os.stat(ev / name).st_mode)
        assert mode == 0o444, f"{name} mode should be 0444, got {oct(mode)}"


def test_evidence_dir_mode_0700(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, evidence_dir=ev)
    mode = stat.S_IMODE(os.stat(ev).st_mode)
    assert mode == 0o700, f"evidence dir mode should be 0700, got {oct(mode)}"


def test_evidence_raw_robots_content(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, evidence_dir=ev)
    assert (ev / "raw_robots.bin").read_bytes() == ROBOTS_BODY


def test_evidence_raw_content_content(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, evidence_dir=ev)
    assert (ev / "raw_content.bin").read_bytes() == CONTENT_BODY


def test_evidence_receipt_is_canonical_json(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([_robots_response(), _content_response()])
    receipt = _run_acquire(tmp_path, inner, evidence_dir=ev)
    raw = (ev / "receipt.json").read_bytes()
    # Must end with newline and be valid JSON
    assert raw.endswith(b"\n")
    parsed = json.loads(raw)
    assert parsed["schema"] == RECEIPT_SCHEMA
    # Must match canonical serialization of the returned receipt dict
    assert raw == _canonical_json(receipt) + b"\n"


def test_evidence_dir_exclusive_fails_if_exists(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    ev.mkdir()
    inner = FakeInnerClient([_robots_response(), _content_response()])
    with pytest.raises(ObservationAcquisitionError, match="EVIDENCE_DIR_EXISTS"):
        _run_acquire(tmp_path, inner, evidence_dir=ev)
    assert len(inner.calls) == 0


# ---------------------------------------------------------------------------
# Error file preservation on failures
# ---------------------------------------------------------------------------

def test_robots_failure_writes_error_file(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([RuntimeError("robots network failure")])
    with pytest.raises(ObservationAcquisitionError):
        _run_acquire(tmp_path, inner, evidence_dir=ev)
    assert (ev / "error.json").exists()
    err = json.loads((ev / "error.json").read_bytes())
    assert err["phase"] == "robots"
    assert not (ev / "receipt.json").exists()


def test_content_failure_writes_error_and_robots_raw(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([
        _robots_response(),
        RuntimeError("content network failure"),
    ])
    with pytest.raises(ObservationAcquisitionError):
        _run_acquire(tmp_path, inner, evidence_dir=ev,
                     wall_clock=_clock(1_000_000.0, 1_000_031.0))
    assert (ev / "raw_robots.bin").exists()
    assert (ev / "error.json").exists()
    err = json.loads((ev / "error.json").read_bytes())
    assert err["phase"] == "content"
    assert not (ev / "receipt.json").exists()


def test_error_file_mode_0444(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    inner = FakeInnerClient([RuntimeError("crash")])
    with pytest.raises(ObservationAcquisitionError):
        _run_acquire(tmp_path, inner, evidence_dir=ev)
    mode = stat.S_IMODE(os.stat(ev / "error.json").st_mode)
    assert mode == 0o444


# ---------------------------------------------------------------------------
# Crash reservation persistence
# ---------------------------------------------------------------------------

def test_crash_robots_get_leaves_reservation(tmp_path: Path) -> None:
    """Reservation persists even when the inner client raises during robots GET."""
    ledger = tmp_path / "ledger.jsonl"
    inner = FakeInnerClient([RuntimeError("crash during robots GET")])
    with pytest.raises(ObservationAcquisitionError):
        _run_acquire(tmp_path, inner, ledger_path=ledger)
    entries = _read_raw_ledger(ledger)
    assert len(entries) == 1
    assert entries[0]["request"]["purpose"] == "robots"
    assert entries[0]["request"]["host"] == TEST_HOST


def test_crash_content_get_leaves_both_reservations(tmp_path: Path) -> None:
    """After content reservation, crash still leaves both reservations intact."""
    ledger = tmp_path / "ledger.jsonl"
    inner = FakeInnerClient([
        _robots_response(),
        RuntimeError("crash during content GET"),
    ])
    with pytest.raises(ObservationAcquisitionError):
        _run_acquire(tmp_path, inner, ledger_path=ledger,
                     wall_clock=_clock(1_000_000.0, 1_000_031.0))
    entries = _read_raw_ledger(ledger)
    assert len(entries) == 2
    assert entries[0]["request"]["purpose"] == "robots"
    assert entries[1]["request"]["purpose"] == "list"


def test_reservation_precedes_get_on_crash(tmp_path: Path) -> None:
    """Prove that when GET crashes, reservation already existed."""
    ledger = tmp_path / "ledger.jsonl"
    reservation_seen_before_crash: list[int] = []

    def robots_hook() -> None:
        reservation_seen_before_crash.append(len(_read_raw_ledger(ledger)))
        raise RuntimeError("deliberate crash")

    inner = FakeInnerClient(
        [None],  # will never reach response — hook raises first
        on_call={0: robots_hook},
    )
    inner._responses[0] = RuntimeError("unreachable")
    # Patch: make fetch raise via on_call hook, which runs before response is returned
    class CrashAfterReservation:
        def __init__(self):
            self.calls = []
        def fetch(self, engine, url, **kw):
            self.calls.append(url)
            n = len(_read_raw_ledger(ledger))
            reservation_seen_before_crash.append(n)
            raise RuntimeError("crash after recording")

    client = CrashAfterReservation()
    route_manifest = _make_route_manifest(tmp_path)
    with pytest.raises(ObservationAcquisitionError):
        acquire_list_observation(
            CONTENT_URL,
            policy=_make_policy(tmp_path),
            allowed_hosts=frozenset({TEST_HOST}),
            route_class=LEVER_LIST_ROUTE_CLASS,
            manifest_path=route_manifest.source_path,
            manifest_sha256=route_manifest.manifest_sha256,
            ledger_path=ledger,
            evidence_dir=tmp_path / "ev",
            inner_client=client,
            wall_clock=_clock(1_000_000.0),
        )
    # The crash client recorded that 1 reservation was already present when GET was called
    assert reservation_seen_before_crash[0] == 1


# ---------------------------------------------------------------------------
# Restart spacing: new adapter reads prior ledger timestamp
# ---------------------------------------------------------------------------

def test_restart_spacing_enforced(tmp_path: Path) -> None:
    """A fresh adapter must respect host interval from a prior adapter's reservation."""
    ledger = tmp_path / "ledger.jsonl"

    # First adapter: make robots reservation at T=1000.
    adapter1 = _LedgeredStaticClient(
        FakeInnerClient([_robots_response()]),
        ledger,
        wall_clock=_clock(1_000.0),
        sleeper=_noop_sleeper,
    )
    adapter1.fetch("static", f"https://{TEST_HOST}/robots.txt")
    entries = _read_raw_ledger(ledger)
    assert len(entries) == 1

    # Second adapter (simulating process restart) at T=1005.
    # sleep_secs = 30 - (1005 - 1000) = 25 should be requested.
    sleep_calls: list[float] = []

    def recording_sleeper(s: float) -> None:
        sleep_calls.append(s)

    # After sleep, clock returns 1031 (past the interval).
    adapter2 = _LedgeredStaticClient(
        FakeInnerClient([_robots_response()]),
        ledger,
        wall_clock=_clock(1_005.0, 1_031.0),
        sleeper=recording_sleeper,
    )
    adapter2.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert len(sleep_calls) == 1
    assert sleep_calls[0] > 0
    entries = _read_raw_ledger(ledger)
    assert len(entries) == 2


def test_restart_no_sleep_when_interval_passed(tmp_path: Path) -> None:
    """No sleep when restarted adapter checks and interval is already satisfied."""
    ledger = tmp_path / "ledger.jsonl"
    adapter1 = _LedgeredStaticClient(
        FakeInnerClient([_robots_response()]),
        ledger,
        wall_clock=_clock(1_000.0),
        sleeper=_noop_sleeper,
    )
    adapter1.fetch("static", f"https://{TEST_HOST}/robots.txt")

    sleep_calls: list[float] = []
    adapter2 = _LedgeredStaticClient(
        FakeInnerClient([_robots_response()]),
        ledger,
        wall_clock=_clock(1_031.0),
        sleeper=lambda s: sleep_calls.append(s),
    )
    adapter2.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert sleep_calls == []


# ---------------------------------------------------------------------------
# Rolling 24h budget
# ---------------------------------------------------------------------------

def _write_ledger_with_n_entries(path: Path, n: int, host: str, ts_base: float) -> None:
    """Write n pre-computed ledger entries directly (for budget testing)."""
    prev_hash = "0" * 64
    entries_bytes = b""
    for i in range(n):
        seq = i + 1
        ts = ts_base + i * 31.0
        kwargs = {
            "retries": 1,
            "retry_delay": 0,
            "follow_redirects": False,
            "max_redirects": 0,
            "stealthy_headers": False,
            "impersonate": None,
            "http3": False,
            "proxy": None,
            "timeout": 30.0,
            "headers": {"User-Agent": "JAA-Public-Research"},
        }
        request = {
            "url": f"https://{host}/robots.txt",
            "host": host,
            "method": "GET",
            "purpose": "robots",
            "effective_kwargs": kwargs,
        }
        payload: dict = {
            "schema": "jaa10.external-request-reservation.v1",
            "sequence": seq,
            "reserved_at_unix": ts,
            "request": request,
            "request_sha256": _sha256(_canonical_json(request)),
            "prev_event_sha256": prev_hash,
        }
        event_hash = _sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode()
        )
        entry = dict(payload)
        entry["event_sha256"] = event_hash
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode() + b"\n"
        entries_bytes += line
        prev_hash = event_hash
    path.write_bytes(entries_bytes)
    path.chmod(0o600)


def test_rolling_budget_admits_60(tmp_path: Path) -> None:
    """60 entries in window does not block the 60th (budget is max-60)."""
    ledger = tmp_path / "ledger.jsonl"
    now = 1_000_000.0
    # Write 59 entries, then the 60th should succeed.
    _write_ledger_with_n_entries(ledger, 59, TEST_HOST, now - 2_000.0)
    inner = FakeInnerClient([_robots_response()])
    adapter = _LedgeredStaticClient(
        inner, ledger, wall_clock=_clock(now), sleeper=_noop_sleeper,
    )
    adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert len(inner.calls) == 1


def test_rolling_budget_exhausted_at_60(tmp_path: Path) -> None:
    """60 entries in the rolling window blocks the 61st."""
    ledger = tmp_path / "ledger.jsonl"
    now = 1_000_000.0
    _write_ledger_with_n_entries(
        ledger, MAX_ROLLING_RESERVATIONS, TEST_HOST, now - 2_000.0
    )
    inner = FakeInnerClient([])
    adapter = _LedgeredStaticClient(
        inner, ledger, wall_clock=_clock(now), sleeper=_noop_sleeper,
    )
    with pytest.raises(ObservationAcquisitionError, match="RATE_DENIED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert len(inner.calls) == 0


def test_rolling_window_excludes_old_entries(tmp_path: Path) -> None:
    """Entries older than 24h do not count toward the rolling budget."""
    ledger = tmp_path / "ledger.jsonl"
    now = 1_000_000.0
    old_ts = now - ROLLING_WINDOW_SECONDS - 2_000.0
    _write_ledger_with_n_entries(
        ledger, MAX_ROLLING_RESERVATIONS, TEST_HOST, old_ts
    )
    # All entries are outside the window → budget is 0 → allowed.
    inner = FakeInnerClient([_robots_response()])
    adapter = _LedgeredStaticClient(
        inner, ledger, wall_clock=_clock(now), sleeper=_noop_sleeper,
    )
    adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert len(inner.calls) == 1


# ---------------------------------------------------------------------------
# Ledger hash chain integrity
# ---------------------------------------------------------------------------

def test_ledger_hash_chain_verified(tmp_path: Path) -> None:
    """Each entry's event_hash and prev_hash chain is verified on every read."""
    ledger = tmp_path / "ledger.jsonl"
    # Write one valid entry then one with corrupted event_hash.
    _write_ledger_with_n_entries(ledger, 1, TEST_HOST, 1000.0)
    lines = ledger.read_bytes().split(b"\n")
    lines = [ln for ln in lines if ln.strip()]
    # Corrupt the event hash of the first entry.
    first = json.loads(lines[0])
    first["event_sha256"] = "bad" * 21 + "d"
    lines[0] = json.dumps(first, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode()
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    inner = FakeInnerClient([_robots_response()])
    adapter = _LedgeredStaticClient(
        inner, ledger, wall_clock=_clock(2000.0), sleeper=_noop_sleeper,
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert len(inner.calls) == 0


# ---------------------------------------------------------------------------
# Fetch kwargs enforcement (inner client sees fixed kwargs)
# ---------------------------------------------------------------------------

def test_inner_client_receives_fixed_kwargs(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, wall_clock=_clock(1_000_000.0, 1_000_031.0))
    for call in inner.calls:
        kw = call["kwargs"]
        assert kw["retries"] == 1
        assert kw["retry_delay"] == 0
        assert kw["follow_redirects"] is False
        assert kw["max_redirects"] == 0
        assert kw["stealthy_headers"] is False
        assert kw["impersonate"] is None
        assert kw["http3"] is False
        assert kw["proxy"] is None
        assert kw["headers"] == {"User-Agent": "JAA-Public-Research"}


def test_inner_client_engine_is_always_static(tmp_path: Path) -> None:
    inner = FakeInnerClient([_robots_response(), _content_response()])
    _run_acquire(tmp_path, inner, wall_clock=_clock(1_000_000.0, 1_000_031.0))
    for call in inner.calls:
        assert call["engine"] == "static"


# ---------------------------------------------------------------------------
# Deterministic success-evidence replay
# ---------------------------------------------------------------------------

def test_success_evidence_replays_without_network(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    policy = _make_policy(tmp_path)
    receipt = _run_acquire(
        tmp_path,
        FakeInnerClient([_robots_response(), _content_response()]),
        evidence_dir=ev,
        policy=policy,
    )
    assert replay_list_observation(ev, policy=policy) == receipt
    assert receipt["request"]["url"] == AUTHORIZED_LEVER_LIST_URL


def test_manifest_member_generalization_and_replay(tmp_path: Path) -> None:
    content_url = (
        "https://api.lever.co/v0/postings/jobgether"
        "?limit=1&mode=json&skip=0"
    )
    manifest = _make_route_manifest(tmp_path)
    policy = _make_policy(tmp_path)
    evidence_dir = tmp_path / "manifest-member-evidence"
    inner = FakeInnerClient([
        _robots_response(),
        _content_response(url=content_url),
    ])

    receipt = acquire_list_observation(
        content_url,
        policy=policy,
        allowed_hosts=frozenset({TEST_HOST}),
        route_class=LEVER_LIST_ROUTE_CLASS,
        manifest_path=manifest.source_path,
        manifest_sha256=manifest.manifest_sha256,
        ledger_path=tmp_path / "manifest-member-ledger.jsonl",
        evidence_dir=evidence_dir,
        inner_client=inner,
        wall_clock=_clock(1_000_000.0, 1_000_031.0),
        sleeper=_noop_sleeper,
        now_fn=lambda: TEST_NOW,
    )

    assert receipt["request"]["url"] == content_url
    assert replay_list_observation(
        evidence_dir,
        policy=policy,
    ) == receipt


def test_receipt_time_follows_robots_retrieval_and_replays(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    policy = _make_policy(tmp_path)
    moments = iter([
        datetime(2026, 8, 2, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 8, 2, 0, 0, 1, tzinfo=timezone.utc),
        datetime(2026, 8, 2, 0, 0, 2, tzinfo=timezone.utc),
    ])
    route_manifest = _make_route_manifest(tmp_path)
    receipt = acquire_list_observation(
        CONTENT_URL,
        policy=policy,
        allowed_hosts=frozenset({TEST_HOST}),
        route_class=LEVER_LIST_ROUTE_CLASS,
        manifest_path=route_manifest.source_path,
        manifest_sha256=route_manifest.manifest_sha256,
        ledger_path=tmp_path / "ledger.jsonl",
        evidence_dir=ev,
        inner_client=FakeInnerClient([_robots_response(), _content_response()]),
        wall_clock=_clock(1_000_000.0, 1_000_031.0),
        sleeper=_noop_sleeper,
        now_fn=lambda: next(moments),
    )
    assert receipt["robots_binding"]["retrieved_at"] < receipt["acquired_at"]
    assert replay_list_observation(ev, policy=policy) == receipt


@pytest.mark.parametrize(
    ("name", "old", "new"),
    [
        ("raw_content.bin", b"job1", b"job2"),
        (
            "content_response_accepted.json",
            b'"content-type":"application/json"',
            b'"content-type":"text/html"',
        ),
        ("receipt.json", b'"certifies_slice":false', b'"certifies_slice":true'),
    ],
)
def test_replay_rejects_modified_evidence(
    tmp_path: Path,
    name: str,
    old: bytes,
    new: bytes,
) -> None:
    ev = tmp_path / "ev"
    policy = _make_policy(tmp_path)
    _run_acquire(
        tmp_path,
        FakeInnerClient([_robots_response(), _content_response()]),
        evidence_dir=ev,
        policy=policy,
    )
    path = ev / name
    path.chmod(0o600)
    raw = path.read_bytes()
    assert old in raw
    path.write_bytes(raw.replace(old, new, 1))
    path.chmod(0o444)
    with pytest.raises(ObservationAcquisitionError, match="REPLAY_REJECTED"):
        replay_list_observation(ev, policy=policy)


def test_replay_rejects_extra_evidence_file(tmp_path: Path) -> None:
    ev = tmp_path / "ev"
    policy = _make_policy(tmp_path)
    _run_acquire(
        tmp_path,
        FakeInnerClient([_robots_response(), _content_response()]),
        evidence_dir=ev,
        policy=policy,
    )
    (ev / "unexpected").write_bytes(b"unexpected")
    with pytest.raises(ObservationAcquisitionError, match="missing or extra"):
        replay_list_observation(ev, policy=policy)
