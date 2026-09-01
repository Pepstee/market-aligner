"""Hermetic sanity-review backend for synthetic fixture and acceptance tests only."""

from __future__ import annotations

import json
from pathlib import Path

from llm.client import Backend, LLMClient, LLMResponse

from .application_sanity_review import (
    RESULT_SCHEMA_VERSION,
    SanityReviewReceipt,
    package_from_application,
    review_application_package,
)


class FixturePassBackend(Backend):
    """Scripted PASS transport; never selected by production configuration."""

    name = "scripted_fixture_test"

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        return LLMResponse(
            text=json.dumps(
                {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "verdict": "pass",
                    "findings": [],
                }
            ),
            model="scripted-fixture-v1",
        )


def fixture_pass_receipt(
    *,
    source,
    artifacts,
    questions,
    state_root: Path,
    vacancy_requirements=None,
    vacancy_review_material=None,
) -> SanityReviewReceipt:
    client = LLMClient(
        backend=FixturePassBackend(),
        model="scripted-fixture-v1",
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=state_root / "sanity-review-cache",
        usage_log=state_root / "sanity-review-usage.jsonl",
    )
    return review_application_package(
        package_from_application(
            source=source,
            artifacts=artifacts,
            questions=questions,
            vacancy_requirements=vacancy_requirements,
            vacancy_review_material=vacancy_review_material,
        ),
        client=client,
    )


__all__ = ["FixturePassBackend", "fixture_pass_receipt"]
