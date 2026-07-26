"""Fail-closed public-access policy for JAA acquisition.

Robots permission and site-terms review are independent gates.  This module
requires an external human attestation, retains exact robots bytes, and
enforces a conservative per-host request interval before a retriever may make
ordinary public requests.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit


POLICY_SCHEMA = "jaa04.public-access-policy.v1"
USER_AGENT = "JAA-Public-Research"
DEFAULT_DELAY_SECONDS = 10.0
MAX_ATTESTATION_AGE_DAYS = 90


class PublicAccessDenied(RuntimeError):
    """A public request lacks terms or robots authority."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _public_origin(url: str) -> tuple[str, str, str]:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password):
        raise PublicAccessDenied("access policy accepts anonymous public HTTP(S) only")
    host = parsed.hostname.casefold()
    port = f":{parsed.port}" if parsed.port else ""
    return parsed.scheme.casefold(), host, port


def _robots_rules(body: bytes, url: str) -> tuple[bool, float | None]:
    """Apply longest-match robots rules for the named product token."""
    groups: list[dict[str, Any]] = []
    agents: list[str] = []
    rules: list[tuple[bool, str]] = []
    delay: float | None = None
    directives_started = False

    def finish() -> None:
        nonlocal agents, rules, delay, directives_started
        if agents:
            groups.append({"agents": agents, "rules": rules, "delay": delay})
        agents, rules, delay, directives_started = [], [], None, False

    for source_line in body.decode("utf-8", "replace").splitlines():
        line = source_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        name, value = (part.strip() for part in line.split(":", 1))
        name = name.casefold()
        if name == "user-agent":
            if directives_started:
                finish()
            agents.append(value.casefold())
            continue
        if not agents:
            continue
        directives_started = True
        if name in {"allow", "disallow"}:
            if value or name == "allow":
                rules.append((name == "allow", value))
        elif name == "crawl-delay":
            try:
                parsed_delay = float(value)
            except ValueError:
                continue
            if parsed_delay >= 0:
                delay = parsed_delay
    finish()

    product = USER_AGENT.casefold()
    selected: list[dict[str, Any]] = []
    specificity = -1
    for group in groups:
        matches = [
            0 if agent == "*" else len(agent)
            for agent in group["agents"]
            if agent == "*" or agent in product
        ]
        if not matches:
            continue
        score = max(matches)
        if score > specificity:
            selected, specificity = [group], score
        elif score == specificity:
            selected.append(group)
    if not selected:
        return True, None

    parsed_url = urlsplit(url)
    target = parsed_url.path or "/"
    if parsed_url.query:
        target += "?" + parsed_url.query
    matches: list[tuple[int, bool]] = []
    declared_delays: list[float] = []
    for group in selected:
        if group["delay"] is not None:
            declared_delays.append(float(group["delay"]))
        for allowed, pattern in group["rules"]:
            anchored = pattern.endswith("$")
            raw_pattern = pattern[:-1] if anchored else pattern
            expression = re.escape(raw_pattern).replace(r"\*", ".*")
            expression = "^" + expression + ("$" if anchored else "")
            if re.search(expression, target):
                specificity_length = len(raw_pattern.replace("*", ""))
                matches.append((specificity_length, allowed))
    if not matches:
        return True, max(declared_delays) if declared_delays else None
    longest = max(length for length, _ in matches)
    # RFC 9309 chooses Allow when equally specific rules conflict.
    allowed = any(value for length, value in matches if length == longest)
    return allowed, max(declared_delays) if declared_delays else None


@dataclass(frozen=True)
class TermsAttestation:
    host: str
    terms_url: str
    determination: str
    reviewed_at: str
    reviewed_by: str
    reviewer_type: str
    notes: str


@dataclass(frozen=True)
class RobotsReceipt:
    host: str
    robots_url: str
    final_url: str
    status_code: int
    content_sha256: str
    raw_response_ref: str
    redirect_history: list[dict[str, Any]]
    retrieved_at: str
    user_agent: str
    requested_url: str
    allowed: bool
    crawl_delay_seconds: float
    terms_policy_sha256: str
    terms_attestation: dict[str, str]


class PublicAccessPolicy:
    """Validated human terms-review attestations keyed by exact hostname."""

    def __init__(
        self,
        attestations: Mapping[str, TermsAttestation],
        *,
        policy_sha256: str,
        now: datetime | None = None,
    ) -> None:
        self.attestations = dict(attestations)
        self.policy_sha256 = policy_sha256
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        now: datetime | None = None,
    ) -> "PublicAccessPolicy":
        raw = path.read_bytes()
        payload = json.loads(raw)
        records = payload.get("hosts")
        if payload.get("schema_version") != POLICY_SCHEMA:
            raise ValueError(f"access policy must use {POLICY_SCHEMA}")
        if not isinstance(records, list) or not records:
            raise ValueError("access policy requires host attestations")
        if hashlib.sha256(_canonical(records)).hexdigest() != payload.get("records_hash"):
            raise ValueError("access policy records hash mismatch")
        attestations: dict[str, TermsAttestation] = {}
        required = {
            "host", "terms_url", "determination", "reviewed_at",
            "reviewed_by", "reviewer_type", "notes",
        }
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        for record in records:
            if not isinstance(record, dict) or set(record) != required:
                raise ValueError("access attestations have an invalid field set")
            if any(not isinstance(record[key], str) or not record[key].strip()
                   for key in required):
                raise ValueError("access attestation fields must be non-empty strings")
            attestation = TermsAttestation(**record)
            host = attestation.host.casefold()
            parsed_host = urlsplit("https://" + host)
            if (host != attestation.host or host in attestations
                    or parsed_host.hostname != host or parsed_host.port is not None):
                raise ValueError("access policy hosts must be unique lowercase names")
            terms = urlsplit(attestation.terms_url)
            if terms.scheme != "https" or not terms.hostname:
                raise ValueError("terms review must cite a public HTTPS URL")
            if attestation.determination != "public_read_only_research_permitted":
                raise ValueError("terms review does not permit public read-only research")
            if attestation.reviewer_type != "human_operator":
                raise ValueError("terms review requires human_operator attestation")
            reviewed = datetime.fromisoformat(attestation.reviewed_at.replace("Z", "+00:00"))
            if reviewed.tzinfo is None:
                raise ValueError("terms review timestamp must include a timezone")
            reviewed = reviewed.astimezone(timezone.utc)
            if reviewed > current or current - reviewed > timedelta(days=MAX_ATTESTATION_AGE_DAYS):
                raise ValueError("terms review attestation is future-dated or stale")
            attestations[host] = attestation
        return cls(
            attestations,
            policy_sha256=hashlib.sha256(raw).hexdigest(),
            now=current,
        )

    def require(self, url: str) -> TermsAttestation:
        _, host, _ = _public_origin(url)
        attestation = self.attestations.get(host)
        if attestation is None:
            raise PublicAccessDenied(
                f"POLICY_DENIED: no human terms-review attestation for {host}"
            )
        return attestation


class DenyAllPublicAccess:
    """Safe default when a caller has not supplied human authority."""

    policy_sha256 = ""

    def authorize(self, _url: str) -> RobotsReceipt:
        raise PublicAccessDenied(
            "POLICY_DENIED: JAA public retrieval requires an external access policy"
        )

    def before_request(self, _url: str) -> RobotsReceipt:
        return self.authorize(_url)


class PublicAccessController:
    """Terms, robots and rate gate around one Scrapling client."""

    def __init__(
        self,
        policy: PublicAccessPolicy,
        client: Any,
        cache: Any,
        *,
        default_delay_seconds: float = DEFAULT_DELAY_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if default_delay_seconds < DEFAULT_DELAY_SECONDS:
            raise ValueError(f"public request delay must be at least {DEFAULT_DELAY_SECONDS:g} seconds")
        self.policy = policy
        self.client = client
        self.cache = cache
        self.default_delay_seconds = float(default_delay_seconds)
        self.clock = clock
        self.sleeper = sleeper
        self.now = now or (lambda: datetime.now(timezone.utc))
        self._receipts: dict[str, RobotsReceipt] = {}
        self._last_request: dict[str, float] = {}

    @property
    def receipts(self) -> tuple[RobotsReceipt, ...]:
        return tuple(self._receipts[host] for host in sorted(self._receipts))

    def _throttle(self, host: str, delay: float) -> None:
        current = self.clock()
        if host in self._last_request:
            remaining = delay - (current - self._last_request[host])
            if remaining > 0:
                self.sleeper(remaining)
                current = self.clock()
        self._last_request[host] = current

    @staticmethod
    def _response_body(response: Mapping[str, Any]) -> bytes:
        try:
            body = base64.b64decode(str(response["body_base64"]), validate=True)
        except (KeyError, ValueError) as exc:
            raise PublicAccessDenied("robots response body is invalid") from exc
        if len(body) != int(response.get("body_bytes", -1)):
            raise PublicAccessDenied("robots response byte count mismatch")
        return body

    def authorize(self, url: str) -> RobotsReceipt:
        scheme, host, port = _public_origin(url)
        attestation = self.policy.require(url)
        if host in self._receipts:
            receipt = self._receipts[host]
            body = self.cache.resolve(receipt.raw_response_ref, receipt.content_sha256)
            allowed = True
            if receipt.status_code == 200:
                allowed, _ = _robots_rules(body, url)
                if not allowed:
                    raise PublicAccessDenied(f"ROBOTS_DISALLOWED: {url}")
            return replace(receipt, requested_url=url, allowed=allowed)
        robots_url = urlunsplit((scheme, host + port, "/robots.txt", "", ""))
        self._throttle(host, self.default_delay_seconds)
        try:
            response = self.client.fetch(
                "static",
                robots_url,
                timeout=self.default_delay_seconds,
                headers={"User-Agent": USER_AGENT},
            )
        except Exception as exc:
            raise PublicAccessDenied(f"ROBOTS_UNAVAILABLE: {host}") from exc
        final_url = str(response.get("url", robots_url))
        _, final_host, _ = _public_origin(final_url)
        redirect_hosts = {
            _public_origin(str(item.get("url", "")))[1]
            for item in response.get("history", ()) or ()
        }
        if final_host != host or redirect_hosts - {host}:
            raise PublicAccessDenied("robots redirect crossed the attested hostname")
        status = int(response.get("status", 0))
        if status >= 500 or status <= 0:
            raise PublicAccessDenied(f"ROBOTS_UNAVAILABLE: HTTP {status}")
        if status == 429:
            raise PublicAccessDenied("ROBOTS_UNAVAILABLE: HTTP 429")
        if status in {401, 403}:
            raise PublicAccessDenied(f"ROBOTS_DISALLOWED: HTTP {status}")
        body = self._response_body(response)
        digest, reference = self.cache.store(body)
        allowed = True
        delay = self.default_delay_seconds
        if 200 <= status < 300:
            allowed, declared = _robots_rules(body, url)
            if declared is not None:
                delay = max(delay, float(declared))
        elif not 400 <= status < 500:
            raise PublicAccessDenied(f"ROBOTS_UNAVAILABLE: HTTP {status}")
        history = [
            {"url": str(item.get("url", "")), "status_code": int(item.get("status", 0))}
            for item in response.get("history", ()) or ()
        ]
        receipt = RobotsReceipt(
            host=host,
            robots_url=robots_url,
            final_url=final_url,
            status_code=status,
            content_sha256=digest,
            raw_response_ref=reference,
            redirect_history=history,
            retrieved_at=self.now().astimezone(timezone.utc).isoformat(),
            user_agent=USER_AGENT,
            requested_url=url,
            allowed=allowed,
            crawl_delay_seconds=delay,
            terms_policy_sha256=self.policy.policy_sha256,
            terms_attestation=asdict(attestation),
        )
        self._receipts[host] = receipt
        if not allowed:
            raise PublicAccessDenied(f"ROBOTS_DISALLOWED: {url}")
        return receipt

    def before_request(self, url: str) -> RobotsReceipt:
        receipt = self.authorize(url)
        self._throttle(receipt.host, receipt.crawl_delay_seconds)
        return receipt
