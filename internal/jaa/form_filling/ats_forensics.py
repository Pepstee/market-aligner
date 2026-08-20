"""Content-addressed forensic evidence for real ATS browser attempts.

The recorder is deliberately diagnostic-only.  It captures enough runtime,
network, console and visible-page evidence to distinguish an ATS validation
failure from an anti-automation challenge without retaining raw candidate form
payloads, cookies, authorization headers or challenge tokens.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from playwright.sync_api import Page


SCHEMA_VERSION = "jaa.live-ats-forensics.v1"
RECEIPT_SCHEMA_VERSION = "jaa.live-ats-forensics-receipt.v1"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVENT_KINDS = frozenset(
    {
        "request",
        "response",
        "request_failed",
        "console",
        "page_error",
        "site_message",
        "screenshot",
        "checkpoint",
    }
)
SAFE_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "content-length",
        "content-type",
        "origin",
        "referer",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
    }
)
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "cf-mitigated",
        "cf-ray",
        "content-length",
        "content-type",
        "location",
        "retry-after",
        "server",
        "x-request-id",
    }
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")
_BEARER = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)\b(?:token|secret|password|passwd|authorization|cookie)\s*[:=]\s*[^\s,;]+"
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _require_digest(value: str, label: str) -> str:
    if not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_once(path: Path, value: bytes, *, label: str) -> None:
    """Publish one immutable object without an overwrite window."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != value:
            raise FileExistsError(f"{label} already contains different evidence")
        return
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def redact_text(value: str) -> str:
    """Remove common candidate and credential material from diagnostic text."""

    text = _EMAIL.sub("<redacted-email>", str(value))
    text = _PHONE.sub("<redacted-phone>", text)
    text = _BEARER.sub("<redacted-authorization>", text)
    return _TOKEN_ASSIGNMENT.sub("<redacted-secret>", text)


def sanitize_url(value: str) -> str:
    """Retain route identity while dropping queries, fragments and token-like paths."""

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "<invalid-or-non-http-url>"
    port = f":{parsed.port}" if parsed.port is not None else ""
    host = f"{parsed.hostname.casefold()}{port}"
    safe_segments: list[str] = []
    for segment in parsed.path.split("/"):
        if len(segment) > 64 or re.fullmatch(r"[A-Za-z0-9_-]{40,}", segment):
            safe_segments.append(f"<segment-sha256:{_sha256_bytes(segment.encode())[:12]}>")
        else:
            safe_segments.append(redact_text(segment))
    return urlunsplit((parsed.scheme.casefold(), host, "/".join(safe_segments), "", ""))


def _redact_value(value: object, *, key: str = "") -> object:
    """Recursively make caller-supplied diagnostic data safe for persistence."""

    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_value(child, key=str(child_key).casefold())
            for child_key, child in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(child, key=key) for child in value]
    if isinstance(value, str):
        return sanitize_url(value) if "url" in key else redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError("forensic diagnostic values must be JSON-compatible")


def _safe_headers(headers: Mapping[str, str], allowed: frozenset[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name).casefold()
        if name not in allowed:
            continue
        value = str(raw_value)
        if name in {"origin", "referer", "location"}:
            value = sanitize_url(value)
        else:
            value = redact_text(value)
        result[name] = value
    return dict(sorted(result.items()))


def runtime_fingerprint(
    *,
    browser_name: str,
    browser_version: str,
    headless: bool,
    user_agent: str,
    locale: str | None = None,
    timezone_id: str | None = None,
    viewport: Mapping[str, int] | None = None,
    launch_args: tuple[str, ...] = (),
) -> dict[str, object]:
    """Return a non-secret runtime identity suitable for comparison across attempts."""

    try:
        playwright_version = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        playwright_version = "not-installed"
    document: dict[str, object] = {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "browser_name": browser_name.strip(),
        "browser_version": browser_version.strip(),
        "playwright_version": playwright_version,
        "headless": bool(headless),
        "user_agent_sha256": _sha256_bytes(user_agent.encode("utf-8")),
        "locale": locale,
        "timezone_id": timezone_id,
        "viewport": dict(viewport) if viewport is not None else None,
        "launch_args": tuple(sorted(redact_text(value) for value in launch_args)),
        "executable_sha256": _sha256_bytes(
            os.fsencode(os.path.realpath(sys.executable))
        ),
    }
    document["runtime_sha256"] = _sha256_json(document)
    return document


@dataclass(frozen=True)
class ATSForensicReceipt:
    attempt_id: str
    manifest_sha256: str
    manifest_path: str
    outcome: str
    event_count: int
    diagnostic_only: bool = True
    release_authority: bool = False
    submission_authority: bool = False
    schema_version: str = RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.attempt_id or self.attempt_id.strip() != self.attempt_id:
            raise ValueError("forensic receipt requires a stable attempt ID")
        _require_digest(self.manifest_sha256, "forensic manifest hash")
        if self.outcome not in {"prepared", "submitted", "blocked", "indeterminate"}:
            raise ValueError("forensic receipt outcome is invalid")
        if self.event_count < 1:
            raise ValueError("forensic receipt requires at least one event")
        if not self.diagnostic_only or self.release_authority or self.submission_authority:
            raise ValueError("forensic receipt cannot carry release or submission authority")
        if self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise ValueError("forensic receipt schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "diagnostic_only": self.diagnostic_only,
            "event_count": self.event_count,
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "outcome": self.outcome,
            "release_authority": self.release_authority,
            "schema_version": self.schema_version,
            "submission_authority": self.submission_authority,
        }


class ATSForensicRecorder:
    """Collect and publish one immutable diagnostic attempt manifest."""

    def __init__(
        self,
        root: Path,
        *,
        attempt_id: str,
        application_id: str,
        ats_name: str,
        application_url: str,
        runtime: Mapping[str, object],
        release_manifest_sha256: str | None = None,
        artifact_set_sha256: str | None = None,
        clock: Any = _utc_now,
    ) -> None:
        for value, label in (
            (attempt_id, "attempt ID"),
            (application_id, "application ID"),
            (ats_name, "ATS name"),
        ):
            if SAFE_IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"forensic {label} is invalid")
        sanitized = sanitize_url(application_url)
        if sanitized == "<invalid-or-non-http-url>":
            raise ValueError("forensic application URL must be HTTP(S)")
        if release_manifest_sha256 is not None:
            _require_digest(release_manifest_sha256, "release manifest hash")
        if artifact_set_sha256 is not None:
            _require_digest(artifact_set_sha256, "artifact-set hash")
        self.root = Path(root)
        self.attempt_id = attempt_id
        self.application_id = application_id
        self.ats_name = ats_name
        self.application_url = sanitized
        self.runtime = json.loads(_canonical_json(dict(runtime)))
        self.release_manifest_sha256 = release_manifest_sha256
        self.artifact_set_sha256 = artifact_set_sha256
        self.clock = clock
        self.started_at = str(clock())
        self._events: list[dict[str, object]] = []
        self._attached = False
        self._finalized = False

    def _event(self, kind: str, payload: Mapping[str, object]) -> None:
        if self._finalized:
            raise RuntimeError("forensic attempt is already finalized")
        if kind not in EVENT_KINDS:
            raise ValueError("forensic event kind is unsupported")
        event = {
            "kind": kind,
            "observed_at": str(self.clock()),
            "payload": json.loads(_canonical_json(_redact_value(payload))),
            "sequence": len(self._events) + 1,
        }
        event["event_sha256"] = _sha256_json(event)
        self._events.append(event)

    def record_request(
        self,
        *,
        method: str,
        url: str,
        resource_type: str,
        headers: Mapping[str, str],
        post_data: str | bytes | None,
    ) -> None:
        raw = (
            post_data.encode("utf-8")
            if isinstance(post_data, str)
            else post_data
        )
        self._event(
            "request",
            {
                "body_bytes": len(raw) if raw is not None else 0,
                "body_sha256": _sha256_bytes(raw) if raw is not None else None,
                "headers": _safe_headers(headers, SAFE_REQUEST_HEADERS),
                "method": method.upper(),
                "resource_type": resource_type,
                "url": sanitize_url(url),
            },
        )

    def record_response(
        self,
        *,
        status: int,
        url: str,
        headers: Mapping[str, str],
    ) -> None:
        self._event(
            "response",
            {
                "headers": _safe_headers(headers, SAFE_RESPONSE_HEADERS),
                "status": int(status),
                "url": sanitize_url(url),
            },
        )

    def record_request_failed(
        self, *, method: str, url: str, resource_type: str, failure: str
    ) -> None:
        self._event(
            "request_failed",
            {
                "failure": redact_text(failure),
                "method": method.upper(),
                "resource_type": resource_type,
                "url": sanitize_url(url),
            },
        )

    def record_console(self, *, level: str, text: str, source_url: str = "") -> None:
        self._event(
            "console",
            {
                "level": level.casefold(),
                "source_url": sanitize_url(source_url) if source_url else None,
                "text": redact_text(text),
            },
        )

    def record_page_error(self, text: str) -> None:
        self._event("page_error", {"text": redact_text(text)})

    def record_site_message(self, text: str, *, classification: str) -> None:
        if classification not in {"validation", "challenge", "spam", "success", "other"}:
            raise ValueError("site-message classification is unsupported")
        self._event(
            "site_message",
            {"classification": classification, "text": redact_text(text)},
        )

    def record_checkpoint(self, name: str, **details: object) -> None:
        self._event(
            "checkpoint",
            {"details": json.loads(_canonical_json(details)), "name": name},
        )

    def record_screenshot(self, image: bytes, *, label: str) -> str:
        digest = _sha256_bytes(image)
        object_path = self.root / "objects" / digest[:2] / f"{digest}.png"
        _write_once(object_path, image, label="forensic screenshot object")
        self._event(
            "screenshot",
            {
                "bytes": len(image),
                "label": label,
                "object_path": str(object_path.relative_to(self.root)),
                "sha256": digest,
            },
        )
        return digest

    def attach_playwright(self, page: "Page") -> None:
        """Attach passive observers; this method never drives or submits the page."""

        if self._attached:
            raise RuntimeError("forensic recorder is already attached")
        self._attached = True

        def on_request(request: Any) -> None:
            if self._finalized:
                return
            self.record_request(
                method=request.method,
                url=request.url,
                resource_type=request.resource_type,
                headers=request.headers,
                post_data=request.post_data,
            )

        def on_response(response: Any) -> None:
            if self._finalized:
                return
            self.record_response(
                status=response.status,
                url=response.url,
                headers=response.headers,
            )

        def on_request_failed(request: Any) -> None:
            if self._finalized:
                return
            self.record_request_failed(
                method=request.method,
                url=request.url,
                resource_type=request.resource_type,
                failure=request.failure or "unknown request failure",
            )

        def on_console(message: Any) -> None:
            if self._finalized:
                return
            location = message.location or {}
            self.record_console(
                level=message.type,
                text=message.text,
                source_url=str(location.get("url", "")),
            )

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_request_failed)
        page.on("console", on_console)
        page.on(
            "pageerror",
            lambda error: None if self._finalized else self.record_page_error(str(error)),
        )

    def capture_page(self, page: "Page", *, label: str) -> str:
        self.record_checkpoint(
            "page_state",
            label=label,
            title=redact_text(page.title()),
            url=sanitize_url(page.url),
        )
        sensitive_controls = page.locator(
            "input, textarea, select, [contenteditable='true']"
        )
        return self.record_screenshot(
            page.screenshot(
                full_page=True,
                mask=[sensitive_controls],
                mask_color="#111111",
            ),
            label=label,
        )

    @property
    def finalized(self) -> bool:
        return self._finalized

    def finalize(
        self,
        *,
        outcome: str,
        failure_class: str | None = None,
        receipt_url: str | None = None,
    ) -> ATSForensicReceipt:
        if self._finalized:
            raise RuntimeError("forensic attempt is already finalized")
        if outcome not in {"prepared", "submitted", "blocked", "indeterminate"}:
            raise ValueError("forensic outcome is invalid")
        if not self._events:
            raise ValueError("forensic attempt cannot finalize without evidence")
        if outcome in {"blocked", "indeterminate"} and not failure_class:
            raise ValueError("failed forensic attempt requires a failure class")
        if failure_class is not None and SAFE_IDENTIFIER.fullmatch(failure_class) is None:
            raise ValueError("forensic failure class must be a stable code")
        manifest = {
            "application_id": self.application_id,
            "application_url": self.application_url,
            "artifact_set_sha256": self.artifact_set_sha256,
            "ats_name": self.ats_name,
            "attempt_id": self.attempt_id,
            "diagnostic_only": True,
            "events": self._events,
            "failure_class": failure_class,
            "finished_at": str(self.clock()),
            "outcome": outcome,
            "receipt_url": sanitize_url(receipt_url) if receipt_url else None,
            "release_authority": False,
            "release_manifest_sha256": self.release_manifest_sha256,
            "runtime": self.runtime,
            "schema_version": SCHEMA_VERSION,
            "started_at": self.started_at,
            "submission_authority": False,
        }
        manifest_sha256 = _sha256_json(manifest)
        manifest["manifest_sha256"] = manifest_sha256
        manifests = self.root / "manifests"
        manifests.mkdir(parents=True, exist_ok=True)
        path = manifests / f"{self.attempt_id}.json"
        encoded = (_canonical_json(manifest) + "\n").encode("utf-8")
        _write_once(path, encoded, label="forensic attempt ID")
        self._finalized = True
        return ATSForensicReceipt(
            attempt_id=self.attempt_id,
            manifest_sha256=manifest_sha256,
            manifest_path=str(path.relative_to(self.root)),
            outcome=outcome,
            event_count=len(self._events),
        )


def verify_forensic_receipt(root: Path, receipt: ATSForensicReceipt) -> dict[str, object]:
    """Offline verification of a manifest, its event chain and screenshot objects."""

    if not isinstance(receipt, ATSForensicReceipt):
        raise TypeError("forensic verification requires ATSForensicReceipt")
    root = Path(root).resolve(strict=True)
    path = (root / receipt.manifest_path).resolve(strict=True)
    if not path.is_relative_to(root) or path.parent != root / "manifests":
        raise ValueError("forensic manifest path escapes its evidence root")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    claimed = manifest.pop("manifest_sha256")
    if claimed != receipt.manifest_sha256 or _sha256_json(manifest) != claimed:
        raise ValueError("forensic manifest hash differs from receipt")
    events = manifest.get("events")
    if not isinstance(events, list) or len(events) != receipt.event_count:
        raise ValueError("forensic event count differs from receipt")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("diagnostic_only") is not True
        or manifest.get("release_authority") is not False
        or manifest.get("submission_authority") is not False
    ):
        raise ValueError("forensic manifest attempted to claim authority")
    for expected_sequence, event in enumerate(events, start=1):
        if event.get("sequence") != expected_sequence:
            raise ValueError("forensic event sequence is invalid")
        event_copy = dict(event)
        event_hash = event_copy.pop("event_sha256", None)
        if event_hash != _sha256_json(event_copy):
            raise ValueError("forensic event hash is invalid")
        if event.get("kind") == "screenshot":
            payload = event.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("forensic screenshot payload is invalid")
            object_path = (root / str(payload.get("object_path"))).resolve(strict=True)
            if not object_path.is_relative_to(root / "objects"):
                raise ValueError("forensic screenshot path escapes its evidence root")
            data = object_path.read_bytes()
            if _sha256_bytes(data) != payload.get("sha256"):
                raise ValueError("forensic screenshot object is invalid")
    if manifest.get("outcome") != receipt.outcome:
        raise ValueError("forensic outcome differs from receipt")
    if manifest.get("attempt_id") != receipt.attempt_id:
        raise ValueError("forensic attempt identity differs from receipt")
    return {**manifest, "manifest_sha256": claimed}
