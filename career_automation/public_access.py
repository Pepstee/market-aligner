"""Fail-closed public-access policy for JAA acquisition.

Robots permission and site-terms review are independent gates.  This module
requires an external human attestation, retains exact robots bytes, and
enforces a conservative per-host request interval before a retriever may make
ordinary public requests.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit


POLICY_SCHEMA = "jaa04.public-access-policy.v1"
USER_AGENT = "JAA-Public-Research"
DEFAULT_DELAY_SECONDS = 10.0
MAX_ATTESTATION_AGE_DAYS = 90
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_UNRESERVED_OCTETS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


class PublicAccessDenied(RuntimeError):
    """A public request lacks terms or robots authority."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def policy_records_hash(records: Any) -> str:
    """Return the single canonical identity used by policy writers/readers."""
    return hashlib.sha256(_canonical(records)).hexdigest()


def _require_public_host(host: str) -> None:
    if host == "localhost" or host.endswith(".localhost"):
        raise PublicAccessDenied("access policy accepts public hosts only")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        return
    if not literal.is_global:
        raise PublicAccessDenied("access policy accepts public hosts only")


def _public_origin(url: str) -> tuple[str, str, str]:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password):
        raise PublicAccessDenied("access policy accepts anonymous public HTTP(S) only")
    host = parsed.hostname.casefold()
    _require_public_host(host)
    port = f":{parsed.port}" if parsed.port else ""
    return parsed.scheme.casefold(), host, port


def _canonical_robots_octets(value: str) -> str:
    """Canonicalize a REP path while preserving reserved encoded octets."""
    canonical: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if (character == "%" and index + 2 < len(value)
                and value[index + 1] in _HEX_DIGITS
                and value[index + 2] in _HEX_DIGITS):
            octet = int(value[index + 1:index + 3], 16)
            if octet in _UNRESERVED_OCTETS:
                canonical.append(chr(octet))
            else:
                canonical.append(f"%{octet:02X}")
            index += 3
            continue
        for octet in character.encode("utf-8"):
            if 0x21 <= octet <= 0x7E and octet != ord("%"):
                canonical.append(chr(octet))
            else:
                canonical.append(f"%{octet:02X}")
        index += 1
    return "".join(canonical)


def _canonical_octet_length(value: str) -> int:
    """Count canonical REP octets rather than percent-encoding characters."""
    length = 0
    index = 0
    while index < len(value):
        if (value[index] == "%" and index + 2 < len(value)
                and value[index + 1] in _HEX_DIGITS
                and value[index + 2] in _HEX_DIGITS):
            index += 3
        else:
            index += 1
        length += 1
    return length


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
        if name in {"allow", "disallow"}:
            directives_started = True
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
    # RFC 9309 section 2.2.1 matches the crawler's product token exactly,
    # case-insensitively, and combines every group for that token.  "*" is a
    # fallback only when no exact group exists.  Treating an arbitrary
    # substring (for example "public") as a more-specific match for
    # "JAA-Public-Research" can select rules meant for a different crawler.
    selected = [
        group for group in groups
        if product in group["agents"]
    ]
    if not selected:
        selected = [
            group for group in groups
            if "*" in group["agents"]
        ]
    if not selected:
        return True, None

    parsed_url = urlsplit(url)
    target = parsed_url.path or "/"
    if parsed_url.query:
        target += "?" + parsed_url.query
    target = _canonical_robots_octets(target)
    matches: list[tuple[int, bool]] = []
    declared_delays: list[float] = []
    for group in selected:
        if group["delay"] is not None:
            declared_delays.append(float(group["delay"]))
        for allowed, pattern in group["rules"]:
            anchored = pattern.endswith("$")
            raw_pattern = _canonical_robots_octets(
                pattern[:-1] if anchored else pattern
            )
            expression = re.escape(raw_pattern).replace(r"\*", ".*")
            expression = "^" + expression + ("$" if anchored else "")
            if re.search(expression, target):
                specificity_length = _canonical_octet_length(
                    raw_pattern.replace("*", "")
                )
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
        if policy_records_hash(records) != payload.get("records_hash"):
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
            try:
                _require_public_host(host)
            except PublicAccessDenied as exc:
                raise ValueError("access policy accepts public hosts only") from exc
            try:
                terms_scheme, _, _ = _public_origin(attestation.terms_url)
            except PublicAccessDenied as exc:
                raise ValueError(
                    "terms review must cite anonymous public HTTPS"
                ) from exc
            if terms_scheme != "https":
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
            if 200 <= receipt.status_code < 300:
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


def replay_access_receipt(
    value: Mapping[str, Any],
    cache: Any,
    *,
    content_urls: tuple[str, ...],
    content_retrieved_at: str,
    policies: Mapping[str, PublicAccessPolicy] | None = None,
) -> RobotsReceipt:
    """Replay one embedded access decision against exact robots and policy bytes.

    ``policies`` is optional only for the in-process dossier validation that
    precedes publication. Certification supplies it and thereby turns the
    embedded attestation from a self-declared claim into an exact match for an
    operator-presented, schema-validated policy file.
    """
    required = {item.name for item in fields(RobotsReceipt)}
    if not isinstance(value, Mapping) or set(value) != required:
        raise ValueError("access receipt has an invalid field set")
    try:
        receipt = RobotsReceipt(**dict(value))
    except TypeError as exc:
        raise ValueError("access receipt is malformed") from exc
    if not content_urls or any(not isinstance(url, str) or not url for url in content_urls):
        raise ValueError("access receipt has no content URL identity")
    try:
        origins = {_public_origin(url) for url in content_urls}
        receipt_origin = _public_origin(receipt.requested_url)
        robots_origin = _public_origin(receipt.robots_url)
        final_origin = _public_origin(receipt.final_url)
    except (PublicAccessDenied, ValueError) as exc:
        raise ValueError("access receipt contains a non-public URL") from exc
    hosts = {origin[1] for origin in origins}
    if (hosts != {receipt.host.casefold()} or receipt_origin[1] != receipt.host.casefold()
            or robots_origin != receipt_origin or final_origin != receipt_origin):
        raise ValueError("access receipt host differs from captured content")
    expected_robots = urlunsplit(
        (receipt_origin[0], receipt_origin[1] + receipt_origin[2], "/robots.txt", "", "")
    )
    final_robots = urlsplit(receipt.final_url)
    if (receipt.robots_url != expected_robots
            or final_robots.path != "/robots.txt"
            or final_robots.query
            or final_robots.fragment):
        raise ValueError("access receipt robots identity is invalid")
    if receipt.requested_url != content_urls[0]:
        raise ValueError("access receipt requested URL differs from the capture")
    if not isinstance(receipt.redirect_history, list):
        raise ValueError("access receipt redirect history is invalid")
    for redirect in receipt.redirect_history:
        if (not isinstance(redirect, Mapping)
                or set(redirect) != {"url", "status_code"}
                or not 300 <= int(redirect["status_code"]) < 400
                or _public_origin(str(redirect["url"]))[1] != receipt.host.casefold()):
            raise ValueError("access receipt robots redirect history is invalid")
    if (receipt.user_agent != USER_AGENT or receipt.allowed is not True
            or type(receipt.crawl_delay_seconds) not in {int, float}
            or float(receipt.crawl_delay_seconds) < DEFAULT_DELAY_SECONDS):
        raise ValueError("access receipt does not prove the required public policy")
    if (type(receipt.status_code) is not int or receipt.status_code <= 0
            or receipt.status_code in {401, 403, 429} or receipt.status_code >= 500
            or not (200 <= receipt.status_code < 300 or 400 <= receipt.status_code < 500)):
        raise ValueError("access receipt contains a terminal robots status")
    if (not isinstance(receipt.content_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.content_sha256)
            or not isinstance(receipt.raw_response_ref, str)
            or not receipt.raw_response_ref):
        raise ValueError("access receipt robots byte identity is invalid")
    try:
        robots_body = cache.resolve(receipt.raw_response_ref, receipt.content_sha256)
    except (OSError, ValueError) as exc:
        raise ValueError("access receipt robots bytes are missing or modified") from exc
    if 200 <= receipt.status_code < 300:
        declared_delays: list[float] = []
        for url in content_urls:
            allowed, delay = _robots_rules(robots_body, url)
            if not allowed:
                raise ValueError("access receipt robots rules disallow captured content")
            if delay is not None:
                declared_delays.append(float(delay))
        if declared_delays and max(declared_delays) > float(receipt.crawl_delay_seconds):
            raise ValueError("access receipt understates the robots crawl delay")

    try:
        retrieved = datetime.fromisoformat(receipt.retrieved_at.replace("Z", "+00:00"))
        content_retrieved = datetime.fromisoformat(content_retrieved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("access receipt timestamps are invalid") from exc
    if retrieved.tzinfo is None or content_retrieved.tzinfo is None or retrieved > content_retrieved:
        raise ValueError("access receipt time is later than the captured content")
    if (not isinstance(receipt.terms_policy_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.terms_policy_sha256)):
        raise ValueError("access receipt policy identity is invalid")
    required_attestation = {item.name for item in fields(TermsAttestation)}
    if (not isinstance(receipt.terms_attestation, Mapping)
            or set(receipt.terms_attestation) != required_attestation):
        raise ValueError("access receipt terms attestation is invalid")
    try:
        attestation = TermsAttestation(**dict(receipt.terms_attestation))
        reviewed = datetime.fromisoformat(attestation.reviewed_at.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("access receipt terms attestation is malformed") from exc
    if (attestation.host != receipt.host.casefold()
            or attestation.reviewer_type != "human_operator"
            or attestation.determination != "public_read_only_research_permitted"
            or reviewed.tzinfo is None or reviewed > retrieved
            or retrieved - reviewed > timedelta(days=MAX_ATTESTATION_AGE_DAYS)):
        raise ValueError("access receipt terms authority is absent, future-dated or stale")
    try:
        terms_scheme, _, _ = _public_origin(attestation.terms_url)
    except PublicAccessDenied as exc:
        raise ValueError(
            "access receipt terms URL is not anonymous public HTTPS"
        ) from exc
    if terms_scheme != "https":
        raise ValueError("access receipt terms URL is not anonymous public HTTPS")
    if policies is not None:
        policy = policies.get(receipt.terms_policy_sha256)
        if policy is None or policy.attestations.get(receipt.host.casefold()) != attestation:
            raise ValueError("access receipt does not match an operator-presented policy")
    return receipt
