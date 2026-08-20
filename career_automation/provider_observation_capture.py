"""Owned, read-only capture boundary for Greenhouse provider semantics.

The production factory consumes the receipt written here.  It never accepts a
caller-built observation as capture authority.  The collector performs a GET,
records the browser-visible and transport bytes, and performs no form or submit
interaction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from .application_archive import ApplicationArchive, VacancyArchiveIdentity
from .evidence_matching import canonical_json


COLLECTOR_IDENTITY = "jaa.playwright-greenhouse-read-only-observer.v4"
COLLECTOR_SOURCE_PATH = "career_automation/provider_observation_capture.py"
_GREENHOUSE_HOSTS = frozenset(
    {
        "boards.greenhouse.io",
        "job-boards.greenhouse.io",
        "job-boards.eu.greenhouse.io",
    }
)
_SENSITIVE_VALUE = re.compile(
    r'(?i)("[^"\\]*(?:token|secret|password|passwd|cookie|csrf|xsrf|api[_-]?key)'
    r'[^"\\]*"\s*:\s*)"(?:\\.|[^"\\])*"'
)
_SENSITIVE_HIDDEN_INPUT = re.compile(
    rb'(?is)(<input\b(?=[^>]*\btype\s*=\s*["\']?hidden["\']?)[^>]*\bvalue\s*=\s*)'
    rb'(["\'])(?:.|\n)*?\2'
)
_SENSITIVE_HIDDEN_INPUT_UNQUOTED = re.compile(
    rb"(?is)(<input\b(?=[^>]*\btype\s*=\s*[\"']?hidden[\"']?)[^>]*"
    rb"\bvalue\s*=\s*)(?![\"'])([^\s>]+)"
)
_BEARER_VALUE = re.compile(rb"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_BASIC_VALUE = re.compile(rb"(?i)\bbasic\s+[a-z0-9+/=]+")
_PLAIN_SECRET_VALUE = re.compile(
    rb"(?i)\b(password|passwd|csrf|xsrf|access[_ -]?token|api[_ -]?key)"
    rb"\s*[:=]\s*([^\s<>,;]+)"
)
_UNSAFE_AFTER_REDACTION = (
    _SENSITIVE_VALUE,
    _SENSITIVE_HIDDEN_INPUT,
    _SENSITIVE_HIDDEN_INPUT_UNQUOTED,
    _BEARER_VALUE,
    _BASIC_VALUE,
    _PLAIN_SECRET_VALUE,
)


def _bytes(document: Mapping[str, object]) -> bytes:
    return (canonical_json(document) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repository_root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError("provider observer requires an exact Git repository")
    return completed.stdout


def exact_clean_head(repository_root: str | Path) -> str:
    """Return HEAD only when every non-ignored worktree byte is committed."""
    root = Path(repository_root).resolve(strict=True)
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("provider observer requires an exact clean HEAD")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("provider observer HEAD identity is invalid")
    return head


def collector_source_identity(
    repository_root: str | Path, *, commit: str = "HEAD"
) -> tuple[bytes, str]:
    root = Path(repository_root).resolve(strict=True)
    source = _git(root, "show", f"{commit}:{COLLECTOR_SOURCE_PATH}")
    return source, _sha256(source)


def _write_create_only(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("provider observation archive path must not be a symlink")
    try:
        with path.open("xb") as handle:
            handle.write(value)
    except FileExistsError:
        if path.read_bytes() != value:
            raise ValueError("content-addressed provider observation object differs")


def _archive_object(root: Path, value: bytes) -> str:
    digest = _sha256(value)
    _write_create_only(root / "objects" / digest[:2] / digest, value)
    return digest


@dataclass(frozen=True)
class ProviderObservationCaptureReceipt:
    manifest_sha256: str
    manifest_path: Path
    observation_sha256: str
    observation: bytes
    observed_at: str
    source_url: str


class ProviderObservationCaptureFailure(RuntimeError):
    """A read-only capture failed after its exact evidence was archived."""

    def __init__(
        self,
        message: str,
        *,
        receipt: ProviderObservationCaptureReceipt,
    ) -> None:
        self.receipt = receipt
        super().__init__(
            f"{message}; archived capture manifest {receipt.manifest_sha256}"
        )


def _redact_sensitive_response(value: bytes) -> bytes:
    text = value.decode("utf-8", errors="replace")
    redacted = _SENSITIVE_VALUE.sub(r'\1"[REDACTED]"', text).encode("utf-8")
    redacted = _SENSITIVE_HIDDEN_INPUT.sub(rb'\1\2[REDACTED]\2', redacted)
    redacted = _SENSITIVE_HIDDEN_INPUT_UNQUOTED.sub(
        rb"\1[REDACTED]", redacted
    )
    redacted = _BEARER_VALUE.sub(b"Bearer [REDACTED]", redacted)
    redacted = _BASIC_VALUE.sub(b"Basic [REDACTED]", redacted)
    redacted = _PLAIN_SECRET_VALUE.sub(rb"\1: [REDACTED]", redacted)
    for pattern in _UNSAFE_AFTER_REDACTION:
        target = (
            redacted.decode("utf-8", errors="replace")
            if isinstance(pattern.pattern, str)
            else redacted
        )
        unsafe = pattern.search(target)
        matched = unsafe.group(0) if unsafe else b""
        if unsafe and "[REDACTED]" not in (
            matched if isinstance(matched, str) else matched.decode(errors="replace")
        ):
            raise ValueError("provider response redaction did not remove a secret")
    return redacted


def _failure_observation(
    *,
    source_url: str,
    observed_at: str,
    code: str,
    status: int | None,
    final_url: str | None = None,
) -> bytes:
    return _bytes(
        {
            "schema_version": "jaa.greenhouse-nonconsequential-canary-failure.v1",
            "provider": "greenhouse",
            "observed_at": observed_at,
            "request": {
                "method": "GET",
                "status": status,
                "url": source_url,
                "final_url": final_url,
            },
            "failure": {"code": code},
            "interaction": {
                "fields_filled": 0,
                "files_uploaded": 0,
                "submit_clicks": 0,
            },
        }
    )


def _persist_failure(
    *,
    archive_root: str | Path,
    repository_root: str | Path,
    source_url: str,
    observed_at: str,
    code: str,
    status: int | None,
    final_url: str | None,
    primary_response: bytes,
    visible_content: bytes,
    network: list[dict[str, object]],
    screenshot: bytes | None,
    screenshot_safety: bytes | None = None,
) -> ProviderObservationCaptureFailure:
    receipt = _persist_capture(
        archive_root=archive_root,
        repository_root=repository_root,
        source_url=source_url,
        observed_at=observed_at,
        observation=_failure_observation(
            source_url=source_url,
            observed_at=observed_at,
            code=code,
            status=status,
            final_url=final_url,
        ),
        primary_response=primary_response or b"[unavailable]\n",
        visible_content=visible_content or b"[unavailable]\n",
        network_events=_bytes(
            {
                "schema_version": "jaa.provider-observation-network.v1",
                "events": network,
            }
        ),
        screenshot=screenshot,
        screenshot_safety=screenshot_safety,
    )
    _terminalize_capture_failure(
        receipt,
        archive_root=archive_root,
        repository_root=repository_root,
        source_url=source_url,
        code=code,
        primary_response=primary_response,
    )
    return ProviderObservationCaptureFailure(code, receipt=receipt)


def _terminalize_capture_failure(
    receipt: ProviderObservationCaptureReceipt,
    *,
    archive_root: str | Path,
    repository_root: str | Path,
    source_url: str,
    code: str,
    primary_response: bytes,
) -> None:
    """Link every failed capture to an append-only terminal JAA attempt."""
    parsed = urlsplit(source_url)
    vacancy_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    capture_manifest = receipt.manifest_path.read_bytes()
    vacancy = VacancyArchiveIdentity(
        job_key=f"greenhouse:{parsed.hostname}:{vacancy_id}",
        vacancy_sha256=_sha256(primary_response or capture_manifest),
        role_title="Provider observation canary",
        company_name=parsed.path.strip("/").split("/", 1)[0] or "Greenhouse",
        source_url=source_url,
    )
    archive = ApplicationArchive(archive_root, repository_root=repository_root)
    attempt = archive.create_attempt(vacancy)
    source = attempt.add_artifact(
        "vacancy.source_identity",
        _bytes(vacancy.document()),
        media_type="application/json",
        disposition="observed",
    )
    capture = attempt.add_artifact(
        "vacancy.capture",
        primary_response or b"[unavailable]\n",
        media_type="text/html",
        disposition="observed",
    )
    provider_receipt = attempt.add_artifact(
        "provider.capture_failure_receipt",
        capture_manifest,
        media_type="application/json",
        disposition="observed",
    )
    result = attempt.add_artifact(
        "submission.result",
        _bytes(
            {
                "state": "abandoned",
                "phase": "before_click_intent",
                "reason_code": code,
                "click_intent_recorded": False,
                "click_may_have_occurred": False,
                "submit_clicks": 0,
            }
        ),
        media_type="application/json",
        disposition="rejected",
    )
    terminal_sha256 = attempt.finalize_terminal(
        outcome="abandoned",
        selected={
            source.role: source.sha256,
            capture.role: capture.sha256,
            provider_receipt.role: provider_receipt.sha256,
            result.role: result.sha256,
        },
    )
    link = _bytes(
        {
            "schema_version": "jaa.provider-capture-terminal-link.v1",
            "capture_manifest_sha256": receipt.manifest_sha256,
            "attempt_id": attempt.attempt_id,
            "terminal_manifest_sha256": terminal_sha256,
        }
    )
    _write_create_only(
        Path(archive_root).resolve(strict=True)
        / "provider-observation-captures"
        / f"{receipt.manifest_sha256}.terminal.json",
        link,
    )


def _persist_capture(
    *,
    archive_root: str | Path,
    repository_root: str | Path,
    source_url: str,
    observed_at: str,
    observation: bytes,
    primary_response: bytes,
    visible_content: bytes,
    network_events: bytes,
    screenshot: bytes | None,
    screenshot_safety: bytes | None = None,
) -> ProviderObservationCaptureReceipt:
    """Persist an owned capture as create-only content-addressed objects."""
    root = Path(archive_root).resolve(strict=True)
    repository = Path(repository_root).resolve(strict=True)
    head = exact_clean_head(repository)
    source, source_sha256 = collector_source_identity(repository)
    if source != Path(__file__).read_bytes():
        raise ValueError("running provider observer differs from exact HEAD")
    parsed = urlsplit(source_url)
    if parsed.scheme != "https" or parsed.hostname not in _GREENHOUSE_HOSTS:
        raise ValueError("provider observer only accepts canonical Greenhouse HTTPS")
    match = re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", parsed.path)
    if match is None or parsed.query or parsed.fragment:
        raise ValueError("provider observer source URL lacks a canonical vacancy ID")
    try:
        stamp = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("provider observer time is invalid") from exc
    if stamp.tzinfo is None:
        raise ValueError("provider observer time must be timezone-aware")
    artifacts = {
        "network_events": _archive_object(root, network_events),
        "observation": _archive_object(root, observation),
        "primary_response": _archive_object(root, primary_response),
        "visible_content": _archive_object(root, visible_content),
    }
    if screenshot is not None:
        if screenshot_safety is None:
            raise ValueError("provider screenshot requires a masking proof")
        artifacts["screenshot"] = _archive_object(root, screenshot)
        artifacts["screenshot_safety"] = _archive_object(root, screenshot_safety)
    elif screenshot_safety is not None:
        artifacts["screenshot_safety"] = _archive_object(root, screenshot_safety)
    manifest = {
        "schema_version": "jaa.provider-observation-capture.v1",
        "capture_mode": "production_live",
        "collector_identity": COLLECTOR_IDENTITY,
        "collector_source_path": COLLECTOR_SOURCE_PATH,
        "collector_source_sha256": source_sha256,
        "repository_commit": head,
        "provider": "greenhouse",
        "source_url": source_url,
        "vacancy_id": match.group(1),
        "observed_at": stamp.astimezone(timezone.utc).isoformat(),
        "interaction": {
            "fields_filled": 0,
            "files_uploaded": 0,
            "submit_clicks": 0,
        },
        "artifacts": artifacts,
    }
    value = _bytes(manifest)
    digest = _archive_object(root, value)
    manifest_path = root / "provider-observation-captures" / f"{digest}.json"
    _write_create_only(manifest_path, value)
    return ProviderObservationCaptureReceipt(
        manifest_sha256=digest,
        manifest_path=manifest_path,
        observation_sha256=artifacts["observation"],
        observation=observation,
        observed_at=str(manifest["observed_at"]),
        source_url=source_url,
    )


def _extract_loader_value(html: str, key: str) -> str:
    patterns = (
        rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"',
        rf"'{re.escape(key)}'\s*:\s*'((?:\\.|[^'\\])*)'",
    )
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            raw = match.group(1)
            try:
                return json.loads(f'"{raw}"')
            except json.JSONDecodeError:
                return raw.replace("\\/", "/")
    raise ValueError(f"Greenhouse loader did not expose {key}")


def _capture_preflight(source_url: str, repository_root: str | Path) -> None:
    repository = Path(repository_root).resolve(strict=True)
    head = exact_clean_head(repository)
    source, _source_sha256 = collector_source_identity(repository, commit=head)
    if source != Path(__file__).read_bytes():
        raise ValueError("running provider observer differs from exact HEAD")
    parsed = urlsplit(source_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _GREENHOUSE_HOSTS
        or re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", parsed.path) is None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("provider observer source URL is not canonical Greenhouse HTTPS")


def _mask_page_for_screenshot(page: object) -> bytes:
    proof = page.evaluate(  # type: ignore[attr-defined]
        """() => {
            let clearedInputs = 0;
            for (const element of document.querySelectorAll('input, textarea')) {
                if ('value' in element && element.value) clearedInputs += 1;
                if ('value' in element) element.value = '';
                element.removeAttribute('value');
            }
            const opaque = document.querySelectorAll('img, svg, canvas, video, iframe');
            const opaqueMediaRemoved = opaque.length;
            opaque.forEach((element) => element.remove());
            let redactedTextNodes = 0;
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            const nodes = [];
            while (walker.nextNode()) nodes.push(walker.currentNode);
            const secret = /(password|passwd|csrf|xsrf|access[_ -]?token|api[_ -]?key|authorization)\\s*[:=]\\s*\\S+/ig;
            for (const node of nodes) {
                const replacement = node.nodeValue.replace(secret, '$1: [REDACTED]');
                if (replacement !== node.nodeValue) redactedTextNodes += 1;
                node.nodeValue = replacement;
            }
            return {clearedInputs, opaqueMediaRemoved, redactedTextNodes};
        }"""
    )
    if not isinstance(proof, Mapping):
        raise ValueError("provider screenshot masking proof is malformed")
    return _bytes(
        {
            "schema_version": "jaa.provider-screenshot-masking-proof.v1",
            "input_values_cleared": int(proof.get("clearedInputs", 0)),
            "opaque_media_removed": int(proof.get("opaqueMediaRemoved", 0)),
            "secret_text_nodes_redacted": int(proof.get("redactedTextNodes", 0)),
            "policy": "clear-fields-remove-opaque-media-redact-labelled-secrets",
        }
    )


def capture_greenhouse_observation(
    *,
    source_url: str,
    archive_root: str | Path,
    repository_root: str | Path,
    timeout_ms: int = 30_000,
) -> ProviderObservationCaptureReceipt:
    """Navigate read-only and capture provider-owned success semantics."""
    _capture_preflight(source_url, repository_root)
    # Import lazily so verification users do not require the browser extra.
    from playwright.sync_api import sync_playwright

    network: list[dict[str, object]] = []
    primary_body = b""
    visible_content = b""
    screenshot: bytes | None = None
    screenshot_safety: bytes | None = None
    final_url: str | None = None
    response_status: int | None = None
    observed_at = datetime.now(timezone.utc).isoformat()
    browser = None
    stage = "playwright_start"
    try:
        with sync_playwright() as playwright:
            stage = "browser_launch"
            browser = playwright.chromium.launch(headless=True)
            stage = "page_create"
            page = browser.new_page()

            def record(response: object) -> None:
                request = response.request
                if request.resource_type not in {"document", "xhr", "fetch", "script"}:
                    return
                parsed_url = urlsplit(response.url)
                network.append(
                    {
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "status": response.status,
                        "url": f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                    }
                )

            page.on("response", record)
            stage = "navigation"
            response = page.goto(
                source_url, wait_until="domcontentloaded", timeout=timeout_ms
            )
            response_status = response.status if response is not None else None
            if response is not None:
                stage = "response_body_read"
                primary_body = _redact_sensitive_response(response.body())
            stage = "hydration_wait"
            page.wait_for_timeout(750)
            stage = "visible_text_read"
            visible_content = _redact_sensitive_response(
                page.locator("body").inner_text().encode("utf-8")
            )
            stage = "screenshot_masking"
            screenshot_safety = _mask_page_for_screenshot(page)
            stage = "screenshot_capture"
            screenshot = page.screenshot(full_page=True)
            final_url = page.url
            stage = "browser_close"
            browser.close()
    except Exception as exc:
        if browser is not None and stage != "browser_close":
            try:
                browser.close()
            except Exception:
                pass
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code=f"provider_{stage}_failed",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
        ) from exc
    if response_status is None or not 200 <= response_status < 300:
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code="provider_http_status_failed",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
        )
    if final_url.rstrip("/") != source_url.rstrip("/"):
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code="provider_route_changed",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
        )
    # The current Greenhouse renderer removes its loader script after hydration.
    # Resolve provider-owned submit semantics from the exact redacted document
    # response, not from mutable post-hydration DOM HTML.
    loader_source = primary_body.decode("utf-8", errors="replace")
    try:
        confirmation_path = _extract_loader_value(
            loader_source, "confirmationPath"
        )
        submit_path = _extract_loader_value(loader_source, "submitPath")
        try:
            confirmation_message = _extract_loader_value(
                loader_source, "confirmation_message"
            )
        except ValueError:
            confirmation_message = _extract_loader_value(
                loader_source, "confirmationMessage"
            )
    except ValueError as exc:
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code="provider_success_semantics_unavailable",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
        ) from exc
    observation = _bytes(
        {
            "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
            "provider": "greenhouse",
            "observed_at": observed_at,
            "request": {"method": "GET", "status": response_status, "url": source_url},
            "provider_loader_paths": {
                "confirmationPath": confirmation_path,
                "confirmation_message": confirmation_message,
                "submitPath": submit_path,
            },
            "interaction": {
                "fields_filled": 0,
                "files_uploaded": 0,
                "submit_clicks": 0,
            },
        }
    )
    return _persist_capture(
        archive_root=archive_root,
        repository_root=repository_root,
        source_url=source_url,
        observed_at=observed_at,
        observation=observation,
        primary_response=primary_body,
        visible_content=visible_content,
        network_events=_bytes(
            {
                "schema_version": "jaa.provider-observation-network.v1",
                "events": network,
            }
        ),
        screenshot=screenshot,
        screenshot_safety=screenshot_safety,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_url")
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--repository-root", default=".")
    args = parser.parse_args()
    receipt = capture_greenhouse_observation(
        source_url=args.source_url,
        archive_root=args.archive_root,
        repository_root=args.repository_root,
    )
    print(
        canonical_json(
            {
                "manifest_path": str(receipt.manifest_path),
                "manifest_sha256": receipt.manifest_sha256,
                "observation_sha256": receipt.observation_sha256,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "COLLECTOR_IDENTITY",
    "COLLECTOR_SOURCE_PATH",
    "ProviderObservationCaptureReceipt",
    "ProviderObservationCaptureFailure",
    "capture_greenhouse_observation",
    "collector_source_identity",
    "exact_clean_head",
]
