#!/usr/bin/env python3
"""Run and archive a read-only Greenhouse provider-semantics canary."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

from career_automation.application_archive import (
    ApplicationArchive,
    VacancyArchiveIdentity,
    verify_complete_attempt,
)
from career_automation.evidence_matching import canonical_json
from career_automation.production_ats_executor import (
    CertifiedGreenhouseSubmitExecutor,
)
from career_automation.production_queue import ProductionCheckpointLedger


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--job-key", required=True)
    parser.add_argument("--company", required=True)
    parser.add_argument("--role-title", required=True)
    parser.add_argument("--fit-score", required=True)
    parser.add_argument("--provider-bundle", action="append", type=Path, default=[])
    arguments = parser.parse_args()

    repository_root = arguments.repository_root.resolve(strict=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        response = page.goto(arguments.url, wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        raw_page = page.content().encode("utf-8")
        visible = page.locator("body").inner_text().encode("utf-8")
        screenshot = page.screenshot(full_page=True)
        provider_paths = page.evaluate(
            """() => {
              const route = window.__remixContext?.state?.loaderData?.[
                'routes/$url_token_.jobs_.$job_post_id'
              ] || {};
              return {
                confirmation_message: route.jobPost?.confirmation_message || null,
                confirmationPath: route.confirmationPath || null,
                submitPath: route.submitPath || null,
              };
            }"""
        )
        title = page.title()
        signals = CertifiedGreenhouseSubmitExecutor._boundary_signals(page)
        final_url = page.url
        browser.close()

    observed_at = datetime.now(timezone.utc).isoformat()
    observation = _json_bytes(
        {
            "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
            "observed_at": observed_at,
            "provider": "greenhouse",
            "request": {
                "url": final_url,
                "method": "GET",
                "status": response.status if response is not None else None,
            },
            "page_title": title,
            "provider_loader_paths": provider_paths,
            "boundary_signals": signals,
            "interaction": {
                "fields_filled": 0,
                "files_uploaded": 0,
                "submit_clicks": 0,
            },
        }
    )
    vacancy = VacancyArchiveIdentity(
        job_key=arguments.job_key,
        vacancy_sha256=hashlib.sha256(raw_page).hexdigest(),
        role_title=arguments.role_title,
        company_name=arguments.company,
        source_url=arguments.url,
    )
    archive = ApplicationArchive(
        arguments.archive_root,
        repository_root=repository_root,
    )
    attempt = archive.create_attempt(vacancy)
    ledger = ProductionCheckpointLedger(archive)
    ledger.record_attempt_started(attempt.attempt_id)
    rows = {}

    def add(role: str, value: bytes, media_type: str):
        row = attempt.add_artifact(
            role,
            value,
            media_type=media_type,
            disposition="observed",
            metadata={"provider": "greenhouse", "phase": "non_consequential_canary"},
        )
        rows[role] = row
        return row

    add("vacancy.source_identity", _json_bytes(vacancy.document()), "application/json")
    add("vacancy.capture", raw_page, "text/html")
    add(
        "vacancy.structured",
        _json_bytes(
            {
                "job_key": vacancy.job_key,
                "company": vacancy.company_name,
                "role_title": vacancy.role_title,
                "source_url": vacancy.source_url,
            }
        ),
        "application/json",
    )
    add(
        "vacancy.assessment",
        _json_bytes(
            {
                "purpose": "non_consequential_provider_canary",
                "fit_score": arguments.fit_score,
                "live": response is not None and response.ok,
                "eligible": True,
                "duplicate": False,
            }
        ),
        "application/json",
    )
    add("provider.success_observation", observation, "application/json")
    for bundle in arguments.provider_bundle:
        add("provider.client_bundle", bundle.resolve(strict=True).read_bytes(), "text/plain")
    add("browser.blocked_screenshot", screenshot, "image/png")
    add("browser.blocked_visible_text", visible, "text/plain")
    add("browser.blocked_state_evidence", observation, "application/json")
    add(
        "browser.redirect_http_evidence",
        _json_bytes(
            {
                "schema_version": "jaa.browser-http-evidence.v1",
                "events": (
                    [
                        {
                            "url": final_url,
                            "status": response.status,
                            "method": "GET",
                            "redirected_from": None,
                        }
                    ]
                    if response is not None
                    else []
                ),
                "availability": (
                    "observed"
                    if response is not None
                    else "no_response_event_observed_after_listener_started"
                ),
            }
        ),
        "application/json",
    )
    add(
        "technical.boundary",
        _json_bytes(
            {
                "classification": "non_consequential_canary",
                "description": "Read-only provider observation stopped before fill or submit.",
                "boundary_signals": signals,
                "future_queue": "technical_boundary" if signals else "provider_observed",
                "secret_value": None,
            }
        ),
        "application/json",
    )
    add(
        "submission.result",
        _json_bytes(
            {
                "state": "blocked",
                "provider": "greenhouse",
                "reason": "non_consequential_canary",
                "submit_clicks": 0,
            }
        ),
        "application/json",
    )
    selected_roles = (
        "vacancy.source_identity",
        "vacancy.capture",
        "technical.boundary",
        "submission.result",
        "browser.blocked_screenshot",
        "browser.blocked_visible_text",
        "browser.blocked_state_evidence",
        "browser.redirect_http_evidence",
        "provider.success_observation",
    )
    terminal_sha256 = attempt.finalize_terminal(
        outcome="blocked",
        selected={role: rows[role].sha256 for role in selected_roles},
        finalized_at=observed_at,
    )
    ledger.record_attempt_terminal(attempt.attempt_id)
    verification = verify_complete_attempt(
        attempt.attempt_id,
        root=archive.root,
        repository_root=repository_root,
    )
    print(
        canonical_json(
            {
                **verification,
                "terminal_manifest_sha256": terminal_sha256,
                "provider_success_observation_sha256": rows[
                    "provider.success_observation"
                ].sha256,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
