"""Negative controls for the JAA-10 external observation acquirer.

Every test here proves that a specific violation is caught before reservation
(zero inner-client calls) or before the ledger is created.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from career_automation.external_observation_acquisition import (
    LEVER_LIST_ROUTE_CLASS,
    ObservationAcquisitionError,
    _LedgeredStaticClient,
    acquire_list_observation,
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    path.write_bytes(json.dumps({
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": policy_records_hash(records),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n")
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
    raw = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode() + b"\n"
    path = tmp_path / "route-manifest.json"
    path.write_bytes(raw)
    path.chmod(0o444)
    return ObservationRouteManifest.load(path, expected_sha256=_sha256(raw))


def _robots_response(host: str = TEST_HOST) -> dict[str, Any]:
    body = ROBOTS_BODY
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


class NeverCalledClient:
    """Raises AssertionError if fetch() is ever invoked."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def fetch(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((args, kwargs))
        raise AssertionError("inner client must not be called before reservation check")


def _noop_sleeper(s: float) -> None:
    pass


def _clock(*ts: float):
    it = iter(ts)
    return lambda: next(it)


def _make_adapter(
    tmp_path: Path,
    inner: Any = None,
    *,
    wall_clock=None,
    sleeper=None,
) -> _LedgeredStaticClient:
    if inner is None:
        inner = NeverCalledClient()
    return _LedgeredStaticClient(
        inner,
        tmp_path / "ledger.jsonl",
        wall_clock=wall_clock or _clock(1_000_000.0),
        sleeper=sleeper or _noop_sleeper,
    )


def _write_ledger(path: Path, n: int, host: str, ts_base: float) -> None:
    prev_hash = "0" * 64
    out = b""
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
        payload = {
            "schema": "jaa10.external-request-reservation.v1",
            "sequence": seq,
            "reserved_at_unix": ts,
            "request": request,
            "request_sha256": _sha256(
                json.dumps(request, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode()
            ),
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
        out += line
        prev_hash = event_hash
    path.write_bytes(out)
    path.chmod(0o600)


# ---------------------------------------------------------------------------
# N1: kwargs allowlist — unknown kwarg fails before reservation
# ---------------------------------------------------------------------------

def test_unknown_kwarg_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*unknown"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt", unknown_arg="bad")
    assert nc.calls == []


def test_cookies_rejected_as_unknown(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      cookies={"session": "abc"})
    assert nc.calls == []


def test_auth_rejected_as_unknown(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      auth=("user", "pass"))
    assert nc.calls == []


def test_body_rejected_as_unknown(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      data=b"payload")
    assert nc.calls == []


def test_method_rejected_as_unknown(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt", method="POST")
    assert nc.calls == []


def test_proxy_rotator_rejected_as_unknown(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      proxy_rotator=object())
    assert nc.calls == []


# ---------------------------------------------------------------------------
# Fixed-value constraints — each fails before reservation
# ---------------------------------------------------------------------------

def test_stealthy_headers_true_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*stealthy_headers"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      stealthy_headers=True)
    assert nc.calls == []


def test_stealthy_headers_truthy_string_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      stealthy_headers="yes")
    assert nc.calls == []


def test_impersonate_nonnull_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*impersonate"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      impersonate="chrome")
    assert nc.calls == []


def test_proxy_nonnull_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*proxy"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      proxy="http://proxy.example.com:8080")
    assert nc.calls == []


def test_follow_redirects_true_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*follow_redirects"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      follow_redirects=True)
    assert nc.calls == []


def test_max_redirects_nonzero_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*max_redirects"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt",
                      max_redirects=5)
    assert nc.calls == []


def test_retries_greater_than_1_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*retries"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt", retries=3)
    assert nc.calls == []


def test_http3_true_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED.*http3"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt", http3=True)
    assert nc.calls == []


# ---------------------------------------------------------------------------
# fetch() path restriction
# ---------------------------------------------------------------------------

def test_fetch_non_robots_path_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/v0/postings")
    assert nc.calls == []


def test_fetch_root_path_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("static", f"https://{TEST_HOST}/")
    assert nc.calls == []


def test_fetch_non_static_engine_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("dynamic", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_fetch_stealth_engine_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch("stealth", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


# ---------------------------------------------------------------------------
# fetch_content() restrictions
# ---------------------------------------------------------------------------

def test_fetch_content_robots_txt_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch_content(f"https://{TEST_HOST}/robots.txt", "list")
    assert nc.calls == []


def test_fetch_content_invalid_purpose_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch_content(CONTENT_URL, "robots")
    assert nc.calls == []


def test_fetch_content_purpose_page_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="FETCH_REJECTED"):
        adapter.fetch_content(CONTENT_URL, "page")
    assert nc.calls == []


def test_fetch_content_without_manifest_rejected_before_reservation(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="hash-bound route manifest"):
        adapter.fetch_content(CONTENT_URL, "list")
    assert nc.calls == []
    assert not (tmp_path / "ledger.jsonl").exists()


# ---------------------------------------------------------------------------
# N4: content URL SSRF validation — fails before reservation
# ---------------------------------------------------------------------------

def test_private_ip_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content("https://192.168.1.1/jobs", "list")
    assert nc.calls == []


def test_localhost_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content("https://localhost/jobs", "list")
    assert nc.calls == []


def test_public_ip_literal_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content("https://8.8.8.8/jobs", "list")
    assert nc.calls == []


def test_ipv6_literal_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content("https://[2001:db8::1]/jobs", "list")
    assert nc.calls == []


def test_userinfo_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content(f"https://user:pass@{TEST_HOST}/v0/postings", "list")
    assert nc.calls == []


def test_fragment_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content(f"https://{TEST_HOST}/v0/postings#section", "list")
    assert nc.calls == []


def test_nondefault_port_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content(f"https://{TEST_HOST}:8443/v0/postings", "list")
    assert nc.calls == []


def test_http_scheme_content_url_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _make_adapter(tmp_path, nc)
    with pytest.raises(ObservationAcquisitionError, match="CONTENT_URL_REJECTED"):
        adapter.fetch_content(f"http://{TEST_HOST}/v0/postings", "list")
    assert nc.calls == []


# ---------------------------------------------------------------------------
# Ledger integrity — each corruption is caught before any GET
# ---------------------------------------------------------------------------

def test_non_utf8_ledger_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"\xff\xfe bad bytes\n")
    ledger.chmod(0o600)
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_non_json_ledger_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"not json at all\n")
    ledger.chmod(0o600)
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_unknown_field_in_ledger_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, 1, TEST_HOST, 1000.0)
    lines = [ln for ln in ledger.read_bytes().split(b"\n") if ln.strip()]
    entry = json.loads(lines[0])
    entry["extra_field"] = "injected"
    lines[0] = json.dumps(entry, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode()
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_broken_prev_hash_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, 2, TEST_HOST, 1000.0)
    lines = [ln for ln in ledger.read_bytes().split(b"\n") if ln.strip()]
    entry = json.loads(lines[1])
    # Rebuild with wrong predecessor hash (we must recompute event hash too).
    entry["prev_event_sha256"] = "b" * 64
    payload = {k: v for k, v in entry.items() if k != "event_sha256"}
    entry["event_sha256"] = _sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()
    )
    lines[1] = json.dumps(entry, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode()
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_wrong_event_hash_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, 1, TEST_HOST, 1000.0)
    lines = [ln for ln in ledger.read_bytes().split(b"\n") if ln.strip()]
    entry = json.loads(lines[0])
    entry["event_sha256"] = "c" * 64
    lines[0] = json.dumps(entry, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode()
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_non_canonical_json_line_rejected(tmp_path: Path) -> None:
    """A ledger line with correct data but non-canonical serialization is rejected."""
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, 1, TEST_HOST, 1000.0)
    lines = [ln for ln in ledger.read_bytes().split(b"\n") if ln.strip()]
    entry = json.loads(lines[0])
    # Re-serialize with non-canonical (different key order / extra spacing)
    non_canonical = json.dumps(entry, ensure_ascii=False,
                               separators=(", ", ": ")).encode()
    lines[0] = non_canonical
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_sequence_gap_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, 2, TEST_HOST, 1000.0)
    lines = [ln for ln in ledger.read_bytes().split(b"\n") if ln.strip()]
    # Remove first line → second starts at sequence 2 but no predecessor.
    ledger.write_bytes(lines[1] + b"\n")
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(2_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="LEDGER_CORRUPT"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


# ---------------------------------------------------------------------------
# Wall-time checks
# ---------------------------------------------------------------------------

def test_now_earlier_than_latest_timestamp_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    future_ts = 9_999_999.0
    _write_ledger(ledger, 1, TEST_HOST, future_ts)
    nc = NeverCalledClient()
    # Supply a now that is earlier than the ledger timestamp.
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=_clock(1_000.0), sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="backwards"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_clock_non_advance_after_sleep_rejected(tmp_path: Path) -> None:
    """If clock returns same value before and after sleep, raise LEDGER_ERROR."""
    ledger = tmp_path / "ledger.jsonl"
    now_ts = 1_000_000.0
    _write_ledger(ledger, 1, TEST_HOST, now_ts - 1.0)  # 1s ago → need 29s sleep
    nc = NeverCalledClient()

    # Both calls return the same value → clock didn't advance.
    same_time = _clock(now_ts, now_ts)
    adapter = _LedgeredStaticClient(
        nc, ledger, wall_clock=same_time, sleeper=_noop_sleeper
    )
    with pytest.raises(ObservationAcquisitionError, match="did not advance"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


def test_non_finite_now_rejected(tmp_path: Path) -> None:
    nc = NeverCalledClient()
    adapter = _LedgeredStaticClient(
        nc, tmp_path / "ledger.jsonl",
        wall_clock=lambda: float("inf"),
        sleeper=_noop_sleeper,
    )
    with pytest.raises(ObservationAcquisitionError, match="non-finite"):
        adapter.fetch("static", f"https://{TEST_HOST}/robots.txt")
    assert nc.calls == []


# ---------------------------------------------------------------------------
# Policy failures — fail before evidence dir / ledger creation
# ---------------------------------------------------------------------------

def test_outside_manifest_route_fails_before_evidence_or_reservation(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    evidence = tmp_path / "evidence"
    client = NeverCalledClient()
    manifest = _make_route_manifest(tmp_path)
    outside_url = (
        "https://api.lever.co/v0/postings/not-listed"
        "?limit=1&mode=json&skip=0"
    )

    with pytest.raises(ObservationAcquisitionError, match="outside.*manifest"):
        acquire_list_observation(
            outside_url,
            policy=_make_policy(tmp_path),
            allowed_hosts=frozenset({TEST_HOST}),
            route_class=LEVER_LIST_ROUTE_CLASS,
            manifest_path=manifest.source_path,
            manifest_sha256=manifest.manifest_sha256,
            ledger_path=ledger,
            evidence_dir=evidence,
            inner_client=client,
        )

    assert client.calls == []
    assert not ledger.exists()
    assert not evidence.exists()


def test_wrong_route_class_fails_before_evidence_or_reservation(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    evidence = tmp_path / "evidence"
    client = NeverCalledClient()
    manifest = _make_route_manifest(tmp_path)

    with pytest.raises(ObservationAcquisitionError, match="unsupported route"):
        acquire_list_observation(
            CONTENT_URL,
            policy=_make_policy(tmp_path),
            allowed_hosts=frozenset({TEST_HOST}),
            route_class="lever_detail.v1",
            manifest_path=manifest.source_path,
            manifest_sha256=manifest.manifest_sha256,
            ledger_path=ledger,
            evidence_dir=evidence,
            inner_client=client,
        )

    assert client.calls == []
    assert not ledger.exists()
    assert not evidence.exists()


def test_manifest_hash_mismatch_fails_before_reservation(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    evidence = tmp_path / "evidence"
    client = NeverCalledClient()
    manifest = _make_route_manifest(tmp_path)

    with pytest.raises(ObservationAcquisitionError, match="MANIFEST_REJECTED"):
        acquire_list_observation(
            CONTENT_URL,
            policy=_make_policy(tmp_path),
            allowed_hosts=frozenset({TEST_HOST}),
            route_class=LEVER_LIST_ROUTE_CLASS,
            manifest_path=manifest.source_path,
            manifest_sha256="0" * 64,
            ledger_path=ledger,
            evidence_dir=evidence,
            inner_client=client,
        )

    assert client.calls == []
    assert not ledger.exists()
    assert not evidence.exists()


def test_host_not_in_policy_rejected(tmp_path: Path) -> None:
    """Content URL host not in policy attestations → fails before ledger."""
    ledger = tmp_path / "ledger.jsonl"
    ev = tmp_path / "ev"
    # Policy has only 'greenhouse.io', not api.lever.co.
    policy = _make_policy(tmp_path, host="greenhouse.io")
    nc = NeverCalledClient()
    manifest = _make_route_manifest(tmp_path)
    with pytest.raises(ObservationAcquisitionError, match="POLICY_DENIED"):
        acquire_list_observation(
            CONTENT_URL,
            policy=policy,
            allowed_hosts=frozenset({TEST_HOST}),
            route_class=LEVER_LIST_ROUTE_CLASS,
            manifest_path=manifest.source_path,
            manifest_sha256=manifest.manifest_sha256,
            ledger_path=ledger,
            evidence_dir=ev,
            inner_client=nc,
        )
    assert nc.calls == []
    assert not ledger.exists()
    assert not ev.exists()


def test_stale_policy_rejected(tmp_path: Path) -> None:
    """PublicAccessPolicy.load() rejects stale attestation."""
    policy_file = tmp_path / "policy.json"
    stale_reviewed_at = "2025-01-01T00:00:00+00:00"  # > 90 days ago from 2026-08-02
    records = [{
        "host": TEST_HOST,
        "terms_url": "https://www.lever.co/legal/terms-of-service",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": stale_reviewed_at,
        "reviewed_by": "Test",
        "reviewer_type": "human_operator",
        "notes": "stale",
    }]
    import hashlib as _hl
    records_hash = _hl.sha256(
        json.dumps(records, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    payload = {
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": records_hash,
    }
    policy_file.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="stale"):
        PublicAccessPolicy.load(policy_file, now=TEST_NOW)


def test_future_policy_rejected(tmp_path: Path) -> None:
    """PublicAccessPolicy.load() rejects future-dated attestation."""
    policy_file = tmp_path / "policy.json"
    future_reviewed_at = "2030-01-01T00:00:00+00:00"
    records = [{
        "host": TEST_HOST,
        "terms_url": "https://www.lever.co/legal/terms-of-service",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": future_reviewed_at,
        "reviewed_by": "Test",
        "reviewer_type": "human_operator",
        "notes": "future",
    }]
    import hashlib as _hl
    records_hash = _hl.sha256(
        json.dumps(records, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    payload = {
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": records_hash,
    }
    policy_file.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="future-dated|stale"):
        PublicAccessPolicy.load(policy_file, now=TEST_NOW)


def test_wrong_determination_policy_rejected(tmp_path: Path) -> None:
    """PublicAccessPolicy.load() rejects non-permitted determination."""
    policy_file = tmp_path / "policy.json"
    records = [{
        "host": TEST_HOST,
        "terms_url": "https://www.lever.co/legal/terms-of-service",
        "determination": "access_denied",
        "reviewed_at": TEST_REVIEWED_AT,
        "reviewed_by": "Test",
        "reviewer_type": "human_operator",
        "notes": "wrong determination",
    }]
    import hashlib as _hl
    records_hash = _hl.sha256(
        json.dumps(records, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    payload = {
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": records_hash,
    }
    policy_file.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="does not permit"):
        PublicAccessPolicy.load(policy_file, now=TEST_NOW)


def test_non_human_operator_policy_rejected(tmp_path: Path) -> None:
    """PublicAccessPolicy.load() rejects non-human_operator reviewer_type."""
    policy_file = tmp_path / "policy.json"
    records = [{
        "host": TEST_HOST,
        "terms_url": "https://www.lever.co/legal/terms-of-service",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": TEST_REVIEWED_AT,
        "reviewed_by": "Test",
        "reviewer_type": "automated_system",
        "notes": "not human",
    }]
    import hashlib as _hl
    records_hash = _hl.sha256(
        json.dumps(records, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    payload = {
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": records_hash,
    }
    policy_file.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="human_operator"):
        PublicAccessPolicy.load(policy_file, now=TEST_NOW)


# ---------------------------------------------------------------------------
# Response integrity — failures after reservation but before receipt
# ---------------------------------------------------------------------------

def test_response_non_200_status_rejected(tmp_path: Path) -> None:
    body = b"not found"
    bad_resp = {
        "url": CONTENT_URL,
        "status": 404,
        "history": [],
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": len(body),
        "headers": {},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "Not Found",
    }
    from career_automation.external_observation_acquisition import _validate_response
    with pytest.raises(ObservationAcquisitionError, match="RESPONSE_REJECTED.*404"):
        _validate_response(bad_resp, TEST_HOST, CONTENT_URL)


def test_response_body_too_large_rejected(tmp_path: Path) -> None:
    from career_automation.external_observation_acquisition import (
        MAX_BODY_BYTES,
        _validate_response,
    )
    big = b"x" * (MAX_BODY_BYTES + 1)
    resp = {
        "url": CONTENT_URL,
        "status": 200,
        "history": [],
        "body_base64": base64.b64encode(big).decode(),
        "body_bytes": len(big),
        "headers": {},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "OK",
    }
    with pytest.raises(ObservationAcquisitionError, match="RESPONSE_REJECTED.*post-transfer"):
        _validate_response(resp, TEST_HOST, CONTENT_URL)


def test_response_body_bytes_mismatch_rejected(tmp_path: Path) -> None:
    from career_automation.external_observation_acquisition import _validate_response
    body = b"hello"
    resp = {
        "url": CONTENT_URL,
        "status": 200,
        "history": [],
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": 999,  # wrong count
        "headers": {},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "OK",
    }
    with pytest.raises(ObservationAcquisitionError, match="RESPONSE_REJECTED.*body_bytes"):
        _validate_response(resp, TEST_HOST, CONTENT_URL)


def test_response_host_mismatch_rejected(tmp_path: Path) -> None:
    from career_automation.external_observation_acquisition import _validate_response
    body = b"data"
    resp = {
        "url": "https://evil.example.com/data",  # different host
        "status": 200,
        "history": [],
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": len(body),
        "headers": {},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "OK",
    }
    with pytest.raises(ObservationAcquisitionError, match="RESPONSE_REJECTED"):
        _validate_response(resp, TEST_HOST, CONTENT_URL)


def test_response_proxy_indicated_rejected(tmp_path: Path) -> None:
    from career_automation.external_observation_acquisition import _validate_response
    body = b"data"
    resp = {
        "url": CONTENT_URL,
        "status": 200,
        "history": [],
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": len(body),
        "headers": {},
        "meta": {"proxy": "http://proxy.example.com"},
        "method": "GET",
        "reason": "OK",
    }
    with pytest.raises(ObservationAcquisitionError, match="RESPONSE_REJECTED.*proxy"):
        _validate_response(resp, TEST_HOST, CONTENT_URL)


def test_response_redirect_history_rejected(tmp_path: Path) -> None:
    from career_automation.external_observation_acquisition import _validate_response
    body = b"data"
    resp = {
        "url": CONTENT_URL,
        "status": 200,
        "history": [{"url": "https://api.lever.co/old", "status": 301}],
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": len(body),
        "headers": {},
        "meta": {"proxy": None},
        "method": "GET",
        "reason": "OK",
    }
    with pytest.raises(ObservationAcquisitionError, match="RESPONSE_REJECTED.*redirect"):
        _validate_response(resp, TEST_HOST, CONTENT_URL)
