"""Read-only Workable/Ashby form diagnostics with no submit capability.

The existing Greenhouse executor and Ashby one-use circuit remain the only
consequential implementations.  This module recovers provider receipt semantics
from the Mac experiment solely for route inspection, actionability checks, and
forensic classification.  It contains no non-trial click primitive.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping
from urllib.parse import urlsplit

from .ats_forensics import sanitize_url

if TYPE_CHECKING:  # pragma: no cover
    from playwright.sync_api import Page


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _origin(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"https://{parsed.hostname.casefold()}{port}"


@dataclass(frozen=True)
class ProviderDiagnosticPolicy:
    provider: str
    version: str
    allowed_origins: tuple[str, ...]
    submit_button_name: str
    success_url_contains: tuple[str, ...]
    success_text: tuple[str, ...]
    blocker_text: Mapping[str, tuple[str, ...]]
    schema_version: str = "jaa.provider-diagnostic-policy.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "jaa.provider-diagnostic-policy.v1":
            raise ValueError("provider diagnostic policy schema is unsupported")
        if not self.provider.strip() or not self.version.strip():
            raise ValueError("provider diagnostic identity is invalid")
        if not self.allowed_origins or any(
            _origin(origin) != origin for origin in self.allowed_origins
        ):
            raise ValueError("provider diagnostic origins must be canonical HTTPS origins")
        if len(set(self.allowed_origins)) != len(self.allowed_origins):
            raise ValueError("provider diagnostic origins must be unique")
        if not self.submit_button_name.strip():
            raise ValueError("provider diagnostic submit label is required")
        if not self.success_url_contains and not self.success_text:
            raise ValueError("provider diagnostic success semantics are absent")
        if any(not value.strip() for value in self.success_url_contains + self.success_text):
            raise ValueError("provider diagnostic success semantics are invalid")
        if any(
            not code.strip() or not messages or any(not message.strip() for message in messages)
            for code, messages in self.blocker_text.items()
        ):
            raise ValueError("provider diagnostic blocker semantics are invalid")

    def document(self) -> dict[str, object]:
        return {
            "allowed_origins": self.allowed_origins,
            "blocker_text": {
                key: tuple(value) for key, value in sorted(self.blocker_text.items())
            },
            "provider": self.provider,
            "schema_version": self.schema_version,
            "submit_button_name": self.submit_button_name,
            "success_text": self.success_text,
            "success_url_contains": self.success_url_contains,
            "version": self.version,
        }

    @property
    def policy_sha256(self) -> str:
        return _sha256_json(self.document())


@dataclass(frozen=True)
class ProviderDiagnosticObservation:
    provider: str
    policy_sha256: str
    sanitized_url: str
    classification: str
    matched_text_sha256: str | None
    submit_control_actionable: bool
    diagnostic_only: bool = True
    consequential_click_authority: bool = False
    submit_click_count: int = 0
    schema_version: str = "jaa.provider-diagnostic-observation.v1"

    def __post_init__(self) -> None:
        if self.classification not in {"ready", "success", "unclassified"} and not self.classification.startswith("blocked:"):
            raise ValueError("provider diagnostic classification is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.policy_sha256):
            raise ValueError("provider diagnostic policy hash is invalid")
        if self.matched_text_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.matched_text_sha256
        ):
            raise ValueError("provider diagnostic match hash is invalid")
        if (
            not self.diagnostic_only
            or self.consequential_click_authority
            or self.submit_click_count != 0
        ):
            raise ValueError("provider diagnostic observation cannot authorize submission")

    def document(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "consequential_click_authority": self.consequential_click_authority,
            "diagnostic_only": self.diagnostic_only,
            "matched_text_sha256": self.matched_text_sha256,
            "policy_sha256": self.policy_sha256,
            "provider": self.provider,
            "sanitized_url": self.sanitized_url,
            "schema_version": self.schema_version,
            "submit_click_count": self.submit_click_count,
            "submit_control_actionable": self.submit_control_actionable,
        }


def inspect_provider_page(
    page: "Page", policy: ProviderDiagnosticPolicy
) -> ProviderDiagnosticObservation:
    """Inspect an intercepted/local fixture; only a Playwright trial click is allowed."""

    if _origin(page.url) not in policy.allowed_origins:
        raise ValueError("provider diagnostic page left the approved origin set")
    body = page.locator("body").inner_text()
    folded = body.casefold()
    matched = next(
        (text for text in policy.success_text if text.casefold() in folded), None
    )
    classification = "success" if matched or any(
        token.casefold() in page.url.casefold()
        for token in policy.success_url_contains
    ) else "unclassified"
    if classification == "unclassified":
        for code, messages in policy.blocker_text.items():
            matched = next(
                (text for text in messages if text.casefold() in folded), None
            )
            if matched:
                classification = f"blocked:{code}"
                break

    locator = page.get_by_role(
        "button",
        name=re.compile(rf"^{re.escape(policy.submit_button_name)}$", re.IGNORECASE),
    )
    actionable = (
        locator.count() == 1 and locator.is_visible() and locator.is_enabled()
    )
    if actionable:
        locator.click(trial=True, timeout=1_000)
    if classification == "unclassified" and actionable:
        classification = "ready"
    return ProviderDiagnosticObservation(
        provider=policy.provider,
        policy_sha256=policy.policy_sha256,
        sanitized_url=sanitize_url(page.url),
        classification=classification,
        matched_text_sha256=(
            hashlib.sha256(matched.encode("utf-8")).hexdigest() if matched else None
        ),
        submit_control_actionable=actionable,
    )


WORKABLE_DIAGNOSTIC_POLICY = ProviderDiagnosticPolicy(
    provider="workable",
    version="mac-e1bb35a-adapted-v1",
    allowed_origins=("https://apply.workable.com",),
    submit_button_name="Submit application",
    success_url_contains=("?success",),
    success_text=("Your application has been submitted successfully.",),
    blocker_text={
        "cloudflare_turnstile": (
            "Verify you are human",
            "Performing security verification",
        ),
        "validation": ("Your form needs corrections",),
    },
)


ASHBY_DIAGNOSTIC_POLICY = ProviderDiagnosticPolicy(
    provider="ashby",
    version="mac-e1bb35a-adapted-v1",
    allowed_origins=("https://jobs.ashbyhq.com",),
    submit_button_name="Submit Application",
    success_url_contains=(),
    success_text=(
        "Your application was successfully submitted.",
        "Thank you so much for your interest in joining",
    ),
    blocker_text={
        "ashby_possible_spam": (
            "Your application submission was flagged as possible spam.",
        ),
        "validation": ("Missing entry for required field",),
    },
)


__all__ = [
    "ASHBY_DIAGNOSTIC_POLICY",
    "WORKABLE_DIAGNOSTIC_POLICY",
    "ProviderDiagnosticObservation",
    "ProviderDiagnosticPolicy",
    "inspect_provider_page",
]
