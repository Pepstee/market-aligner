"""Deterministic vacancy canonicalisation and cross-source deduplication."""

from .deduplication import DeduplicationResult, canonical_key, deduplicate
from .records import vacancy_shell_from_raw

__all__ = ["DeduplicationResult", "canonical_key", "deduplicate", "vacancy_shell_from_raw"]
