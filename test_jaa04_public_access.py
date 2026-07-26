"""Offline adversarial tests for JAA-04 public-access authority."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import career_automation.employer_research as research
from career_automation.employer_research import RawResponseCache, ScraplingPublicRetriever
from career_automation.public_access import (
    DEFAULT_DELAY_SECONDS,
    DenyAllPublicAccess,
    PublicAccessController,
    PublicAccessDenied,
    PublicAccessPolicy,
    RobotsReceipt,
    USER_AGENT,
    replay_access_receipt,
)


NOW = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
HOST = "jobs.example.test"
URL = f"https://{HOST}/jobs/engineer"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _policy(path: Path, *, hosts: tuple[str, ...] = (HOST,),
            reviewer_type: str = "human_operator",
            age_days: int = 1,
            terms_url: str | None = None) -> PublicAccessPolicy:
    records = [{
        "host": host,
        "terms_url": terms_url or f"https://{host}/terms",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": (NOW - timedelta(days=age_days)).isoformat(),
        "reviewed_by": "Test Operator",
        "reviewer_type": reviewer_type,
        "notes": "Public vacancy research reviewed for this offline test.",
    } for host in hosts]
    payload = {
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": hashlib.sha256(_canonical(records)).hexdigest(),
    }
    path.write_bytes(_canonical(payload) + b"\n")
    return PublicAccessPolicy.load(path, now=NOW)


def _response(status: int, body: bytes, *, url: str, history=()) -> dict[str, Any]:
    return {
        "status": status,
        "url": url,
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": len(body),
        "history": list(history),
        "text": body.decode("utf-8", "replace"),
    }


class _Client:
    def __init__(self, robots: dict[str, Any], page: dict[str, Any] | None = None) -> None:
        self.robots, self.page = robots, page
        self.calls: list[tuple[str, str]] = []

    def fetch(self, engine: str, url: str, **_: Any) -> dict[str, Any]:
        self.calls.append((engine, url))
        return self.robots if url.endswith("/robots.txt") else dict(self.page or {})


class _Clock:
    def __init__(self) -> None:
        self.value = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


def _controller(
    tmp_path: Path,
    robots: dict[str, Any],
    *,
    page: dict[str, Any] | None = None,
) -> tuple[PublicAccessController, _Client, RawResponseCache, _Clock]:
    cache = RawResponseCache(tmp_path / "raw")
    client = _Client(robots, page)
    clock = _Clock()
    controller = PublicAccessController(
        _policy(tmp_path / "access.json"),
        client,
        cache,
        clock=clock.monotonic,
        sleeper=clock.sleep,
        now=lambda: NOW,
    )
    return controller, client, cache, clock


def test_missing_or_nonhuman_terms_attestation_denies_before_network(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="human_operator"):
        _policy(tmp_path / "machine.json", reviewer_type="automation")
    policy = _policy(tmp_path / "other.json", hosts=("other.example.test",))
    client = _Client(_response(404, b"", url=f"https://{HOST}/robots.txt"))
    controller = PublicAccessController(policy, client, RawResponseCache(tmp_path / "raw"))
    with pytest.raises(PublicAccessDenied, match="POLICY_DENIED"):
        controller.before_request(URL)
    assert client.calls == []
    with pytest.raises(PublicAccessDenied, match="external access policy"):
        DenyAllPublicAccess().before_request(URL)
    with pytest.raises(ValueError, match="stale"):
        _policy(tmp_path / "stale.json", age_days=91)


@pytest.mark.parametrize("host", ("localhost", "api.localhost", "127.0.0.1", "169.254.1.1"))
def test_private_policy_hosts_are_rejected_before_network(
    tmp_path: Path,
    host: str,
) -> None:
    with pytest.raises(ValueError, match="public hosts"):
        _policy(tmp_path / "private.json", hosts=(host,))


@pytest.mark.parametrize(
    "terms_url",
    (
        f"https://operator:secret@{HOST}/terms",
        "https://localhost/terms",
        "https://127.0.0.1/terms",
    ),
)
def test_nonpublic_terms_url_is_rejected(
    tmp_path: Path,
    terms_url: str,
) -> None:
    with pytest.raises(ValueError, match="anonymous public HTTPS"):
        _policy(
            tmp_path / "nonpublic-terms.json",
            terms_url=terms_url,
        )


@pytest.mark.parametrize("status", (401, 403, 429, 500, 503))
def test_robots_denial_or_unavailability_is_terminal(
    tmp_path: Path,
    status: int,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    controller, client, _, _ = _controller(
        tmp_path,
        _response(status, b"denied", url=robots_url),
    )
    with pytest.raises(PublicAccessDenied, match="ROBOTS_"):
        controller.before_request(URL)
    assert client.calls == [("static", robots_url)]


def test_robots_transport_failure_is_terminal(tmp_path: Path) -> None:
    class BrokenClient:
        def fetch(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise TimeoutError("offline")

    controller = PublicAccessController(
        _policy(tmp_path / "access.json"),
        BrokenClient(),
        RawResponseCache(tmp_path / "raw"),
    )
    with pytest.raises(PublicAccessDenied, match="ROBOTS_UNAVAILABLE"):
        controller.before_request(URL)


def test_robots_disallow_and_longest_allow_are_enforced_from_exact_bytes(
    tmp_path: Path,
) -> None:
    body = (
        f"User-agent: {USER_AGENT}\n"
        "Disallow: /jobs\n"
        "Allow: /jobs/public\n"
        "Crawl-delay: 12\n"
    ).encode()
    robots_url = f"https://{HOST}/robots.txt"
    controller, _, cache, _ = _controller(
        tmp_path,
        _response(200, body, url=robots_url),
    )
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED"):
        controller.before_request(URL)
    public = f"https://{HOST}/jobs/public/engineer"
    receipt = controller.before_request(public)
    assert receipt.allowed
    assert receipt.crawl_delay_seconds == 12
    assert cache.resolve(receipt.raw_response_ref, receipt.content_sha256) == body
    assert receipt.content_sha256 == hashlib.sha256(body).hexdigest()


def test_robots_product_token_matching_is_exact_and_wildcard_is_fallback(
    tmp_path: Path,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    misleading = (
        "User-agent: public\n"
        "Allow: /jobs\n"
        "User-agent: *\n"
        "Disallow: /jobs\n"
    ).encode()
    controller, _, _, _ = _controller(
        tmp_path,
        _response(200, misleading, url=robots_url),
    )
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED"):
        controller.before_request(URL)

    exact = (
        "User-agent: *\n"
        "Disallow: /jobs\n"
        f"User-agent: {USER_AGENT.upper()}\n"
        "Allow: /jobs\n"
        f"User-agent: {USER_AGENT.lower()}\n"
        "Crawl-delay: 14\n"
    ).encode()
    controller, _, _, _ = _controller(
        tmp_path,
        _response(200, exact, url=robots_url),
    )
    receipt = controller.before_request(URL)
    assert receipt.allowed
    assert receipt.crawl_delay_seconds == 14


@pytest.mark.parametrize(
    "other_record",
    (
        "Sitemap: https://jobs.example.test/sitemap.xml",
        "Crawl-delay: 12",
    ),
)
def test_robots_other_records_do_not_split_consecutive_user_agents(
    tmp_path: Path,
    other_record: str,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    body = (
        f"User-agent: {USER_AGENT}\n"
        f"{other_record}\n"
        "User-agent: OtherBot\n"
        "Disallow: /jobs\n"
    ).encode()
    controller, _, _, _ = _controller(
        tmp_path,
        _response(200, body, url=robots_url),
    )
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED"):
        controller.before_request(URL)


@pytest.mark.parametrize(
    ("rule", "path"),
    (
        ("/jobs/%70rivate", "/jobs/private/engineer"),
        ("/jobs/ツ", "/jobs/%E3%83%84"),
        ("/jobs/a%2Fb", "/jobs/a%2fb"),
    ),
)
def test_robots_rules_compare_canonical_octets(
    tmp_path: Path,
    rule: str,
    path: str,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    body = f"User-agent: {USER_AGENT}\nDisallow: {rule}\n".encode()
    controller, _, _, _ = _controller(
        tmp_path,
        _response(200, body, url=robots_url),
    )
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED"):
        controller.before_request(f"https://{HOST}{path}")


def test_robots_encoded_reserved_separator_remains_distinct(
    tmp_path: Path,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    body = f"User-agent: {USER_AGENT}\nDisallow: /jobs/a%2Fb\n".encode()
    controller, _, _, _ = _controller(
        tmp_path,
        _response(200, body, url=robots_url),
    )
    assert controller.before_request(f"https://{HOST}/jobs/a/b").allowed


def test_cached_non_200_success_replays_rules_for_each_url(tmp_path: Path) -> None:
    body = (
        f"User-agent: {USER_AGENT}\n"
        "Disallow: /jobs\n"
        "Allow: /jobs/public\n"
    ).encode()
    robots_url = f"https://{HOST}/robots.txt"
    controller, client, _, _ = _controller(
        tmp_path,
        _response(204, body, url=robots_url),
    )
    public = f"https://{HOST}/jobs/public/engineer"
    assert controller.before_request(public).allowed
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED"):
        controller.before_request(URL)
    assert client.calls == [("static", robots_url)]


def test_absent_robots_is_receipted_and_ten_second_floor_is_enforced(
    tmp_path: Path,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    controller, client, cache, clock = _controller(
        tmp_path,
        _response(404, b"not found", url=robots_url),
    )
    receipt = controller.before_request(URL)
    controller.before_request(URL)
    assert receipt.allowed and receipt.status_code == 404
    assert receipt.crawl_delay_seconds == DEFAULT_DELAY_SECONDS
    assert cache.resolve(receipt.raw_response_ref, receipt.content_sha256) == b"not found"
    assert clock.sleeps == [10.0, 10.0]
    assert client.calls == [("static", robots_url)]


def test_robots_receipts_are_scoped_to_exact_origin(tmp_path: Path) -> None:
    https_url = URL
    http_url = URL.replace("https://", "http://")

    class OriginClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def fetch(self, engine: str, url: str, **_: Any) -> dict[str, Any]:
            self.calls.append((engine, url))
            body = (
                b"User-agent: *\nAllow: /\n"
                if url.startswith("https://")
                else b"User-agent: *\nDisallow: /jobs\n"
            )
            return _response(200, body, url=url)

    client = OriginClient()
    controller = PublicAccessController(
        _policy(tmp_path / "access.json"),
        client,
        RawResponseCache(tmp_path / "raw"),
        clock=_Clock().monotonic,
        sleeper=lambda _: None,
        now=lambda: NOW,
    )
    assert controller.before_request(https_url).allowed
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED"):
        controller.before_request(http_url)
    assert client.calls == [
        ("static", f"https://{HOST}/robots.txt"),
        ("static", f"http://{HOST}/robots.txt"),
    ]


def test_global_ipv6_origin_uses_bracketed_robots_authority(tmp_path: Path) -> None:
    host = "2001:4860:4860::8888"
    url = f"https://[{host}]/jobs/engineer"
    robots_url = f"https://[{host}]/robots.txt"
    policy = _policy(
        tmp_path / "ipv6-access.json",
        hosts=(host,),
        terms_url=f"https://[{host}]/terms",
    )
    client = _Client(
        _response(200, b"User-agent: *\nAllow: /\n", url=robots_url)
    )
    clock = _Clock()
    controller = PublicAccessController(
        policy,
        client,
        RawResponseCache(tmp_path / "raw"),
        clock=clock.monotonic,
        sleeper=clock.sleep,
        now=lambda: NOW,
    )
    receipt = controller.before_request(url)
    assert receipt.robots_url == robots_url
    assert client.calls == [("static", robots_url)]
    assert clock.sleeps == [10.0]


def test_cross_host_robots_redirect_is_rejected(tmp_path: Path) -> None:
    controller, _, _, _ = _controller(
        tmp_path,
        _response(200, b"User-agent: *\nAllow: /\n",
                  url="https://other.example.test/robots.txt"),
    )
    with pytest.raises(PublicAccessDenied, match="crossed"):
        controller.before_request(URL)


def test_same_host_robots_scheme_redirect_replays_exact_bytes(
    tmp_path: Path,
) -> None:
    requested_url = URL.replace("https://", "http://")
    initial_robots = f"http://{HOST}/robots.txt"
    final_robots = f"https://{HOST}/robots.txt"
    controller, _, cache, _ = _controller(
        tmp_path,
        _response(
            200,
            b"User-agent: *\nAllow: /\n",
            url=final_robots,
            history=({"url": initial_robots, "status": 301},),
        ),
    )
    value = asdict(controller.before_request(requested_url))
    replayed = replay_access_receipt(
        value,
        cache,
        content_urls=(requested_url,),
        content_retrieved_at=NOW.isoformat(),
        policies={controller.policy.policy_sha256: controller.policy},
    )
    assert replayed.final_url == final_robots
    assert replayed.redirect_history == [
        {"url": initial_robots, "status_code": 301},
    ]


def test_retriever_never_uses_stealth_and_challenge_is_terminal(
    tmp_path: Path,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    page = _response(403, b"Please complete CAPTCHA", url=URL)
    controller, client, cache, _ = _controller(
        tmp_path,
        _response(404, b"not found", url=robots_url),
        page=page,
    )
    retriever = ScraplingPublicRetriever(cache, access_controller=controller)
    retriever.client = client
    with pytest.raises(PublicAccessDenied, match="ACCESS_DENIED"):
        retriever._fetch(URL)
    assert [engine for engine, _ in client.calls] == ["static", "static"]
    assert "dynamic" not in [engine for engine, _ in client.calls]
    assert "stealth" not in [engine for engine, _ in client.calls]


def test_static_to_dynamic_fallback_throttles_every_stage_without_stealth(
    tmp_path: Path,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    rendered = b"<html><p>Rendered public vacancy evidence.</p></html>" * 4

    class FallbackClient(_Client):
        def fetch(self, engine: str, url: str, **kwargs: Any) -> dict[str, Any]:
            if url.endswith("/robots.txt"):
                return super().fetch(engine, url, **kwargs)
            self.calls.append((engine, url))
            if engine == "static":
                return _response(200, b"short", url=url)
            return _response(200, rendered, url=url)

    cache = RawResponseCache(tmp_path / "raw")
    client = FallbackClient(_response(404, b"not found", url=robots_url))
    clock = _Clock()
    controller = PublicAccessController(
        _policy(tmp_path / "access.json"),
        client,
        cache,
        clock=clock.monotonic,
        sleeper=clock.sleep,
        now=lambda: NOW,
    )
    retriever = ScraplingPublicRetriever(cache, access_controller=controller)
    retriever.client = client
    result, _ = retriever._fetch(URL)
    assert result.engine == "dynamic"
    assert [engine for engine, _ in client.calls] == ["static", "static", "dynamic"]
    assert clock.sleeps == [10.0, 10.0]


def test_page_redirect_to_unattested_host_is_rejected(tmp_path: Path) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    controller, client, cache, _ = _controller(
        tmp_path,
        _response(404, b"not found", url=robots_url),
        page=_response(
            200,
            b"public vacancy evidence " * 20,
            url="https://unattested.example.test/jobs/engineer",
        ),
    )
    retriever = ScraplingPublicRetriever(cache, access_controller=controller)
    retriever.client = client
    with pytest.raises(PublicAccessDenied, match="cross-host"):
        retriever._fetch(URL)


def test_successful_citation_contains_byte_resolvable_access_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    body = json.dumps({
        "title": "Software Engineer",
        "updated_at": "2026-07-25T00:00:00+00:00",
        "description": "Public vacancy evidence " * 20,
    }, separators=(",", ":")).encode()
    controller, client, cache, _ = _controller(
        tmp_path,
        _response(200, b"User-agent: *\nAllow: /\n", url=robots_url),
        page=_response(200, body, url=URL),
    )
    retriever = ScraplingPublicRetriever(cache, access_controller=controller)
    retriever.client = client
    monkeypatch.setattr(research, "_public_url", lambda _: None)
    citation = retriever.retrieve("source", URL, source_kind="official_vacancy")
    assert citation.retrieval_engine == "scrapling-static"
    assert citation.access_receipt is not None
    receipt = RobotsReceipt(**citation.access_receipt)
    assert receipt.terms_attestation["reviewer_type"] == "human_operator"
    assert cache.resolve(receipt.raw_response_ref, receipt.content_sha256).startswith(
        b"User-agent"
    )
    assert asdict(receipt) == citation.access_receipt


@pytest.mark.parametrize(
    "attack",
    (
        "missing-field", "policy-substitution", "terminal-status",
        "delay-understatement", "robots-query",
    ),
)
def test_access_receipt_replay_requires_operator_policy_and_exact_robots_bytes(
    tmp_path: Path,
    attack: str,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    controller, _, cache, _ = _controller(
        tmp_path,
        _response(
            200,
            f"User-agent: {USER_AGENT}\nAllow: /\nCrawl-delay: 10\n".encode(),
            url=robots_url,
        ),
    )
    value = asdict(controller.before_request(URL))
    if attack == "missing-field":
        value.pop("allowed")
    elif attack == "policy-substitution":
        value["terms_policy_sha256"] = "0" * 64
    elif attack == "terminal-status":
        value["status_code"] = 429
    elif attack == "delay-understatement":
        value["crawl_delay_seconds"] = 9.0
    else:
        value["final_url"] += "?attacker-state=1"
    with pytest.raises(ValueError):
        replay_access_receipt(
            value,
            cache,
            content_urls=(URL,),
            content_retrieved_at=NOW.isoformat(),
            policies={controller.policy.policy_sha256: controller.policy},
        )


def test_access_receipt_replay_accepts_exact_operator_policy_and_robots_bytes(
    tmp_path: Path,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    controller, _, cache, _ = _controller(
        tmp_path,
        _response(200, b"User-agent: *\nAllow: /\n", url=robots_url),
    )
    value = asdict(controller.before_request(URL))
    replayed = replay_access_receipt(
        value,
        cache,
        content_urls=(URL,),
        content_retrieved_at=NOW.isoformat(),
        policies={controller.policy.policy_sha256: controller.policy},
    )
    assert replayed == RobotsReceipt(**value)


@pytest.mark.parametrize(
    "terms_url",
    (
        f"https://operator:secret@{HOST}/terms",
        "https://localhost/terms",
        "https://127.0.0.1/terms",
    ),
)
def test_access_receipt_replay_rejects_nonpublic_embedded_terms_without_policy(
    tmp_path: Path,
    terms_url: str,
) -> None:
    robots_url = f"https://{HOST}/robots.txt"
    controller, _, cache, _ = _controller(
        tmp_path,
        _response(200, b"User-agent: *\nAllow: /\n", url=robots_url),
    )
    value = asdict(controller.before_request(URL))
    value["terms_attestation"]["terms_url"] = terms_url
    with pytest.raises(ValueError, match="anonymous public HTTPS"):
        replay_access_receipt(
            value,
            cache,
            content_urls=(URL,),
            content_retrieved_at=NOW.isoformat(),
            policies=None,
        )
