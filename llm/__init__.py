"""
llm/ — the shared "brain" of the Korea Job Scraper.

A horizontal SERVICE (see Architecture.md), not a pipeline stage: both the
scraper (extract_job, rate_axes) and the profiler (assess_portfolio) call in.
The LLM's non-determinism is sealed behind this interface — fixed & versioned
prompts, JSON schemas, temperature≈0, cached and cost-logged.

Public surface:
    from llm import LLMClient, MockBackend, StubBackend
    from llm.capabilities import (
        extract_job, rate_axes, assess_portfolio, normalise_skill,
    )
"""

from __future__ import annotations

from .client import (
    LLMClient,
    MockBackend,
    StubBackend,
    ClaudeCliBackend,
    LLMError,
    make_backend,
)
from .capabilities import (
    extract_job,
    rate_axes,
    assess_portfolio,
    normalise_skill,
    set_client,
    get_client,
)

__all__ = [
    "LLMClient",
    "MockBackend",
    "StubBackend",
    "ClaudeCliBackend",
    "LLMError",
    "make_backend",
    "extract_job",
    "rate_axes",
    "assess_portfolio",
    "normalise_skill",
    "set_client",
    "get_client",
]
