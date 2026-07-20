"""Deterministic hybrid retrieval over evidence-ledger projections.

The evidence ledger remains canonical.  This module builds an in-memory,
rebuildable lexical projection and optionally combines it with semantic scores
produced by a separately versioned embedding service.  Every result retains its
immutable evidence ID.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9+#._/-]*", re.IGNORECASE)


def tokenize(text: str) -> tuple[str, ...]:
    """Return a stable, deliberately small lexical representation."""
    return tuple(match.group(0).casefold() for match in TOKEN_RE.finditer(text))


@dataclass(frozen=True)
class EvidenceDocument:
    evidence_id: str
    text: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id is required")
        if not self.text.strip():
            raise ValueError(f"{self.evidence_id}: text is required")


@dataclass(frozen=True)
class RetrievalResult:
    evidence_id: str
    lexical_score: float
    semantic_score: float | None
    combined_score: float
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class ProjectionManifest:
    profile_version: str
    evidence_ids: tuple[str, ...]
    corpus_hash: str
    tokenizer_version: str = "lexical-v1"


class HybridEvidenceIndex:
    """BM25 lexical retrieval with optional externally supplied semantic scores."""

    def __init__(
        self,
        documents: Iterable[EvidenceDocument],
        *,
        profile_version: str,
        k1: float = 1.5,
        b: float = 0.75,
    ) -> None:
        docs = tuple(documents)
        if not docs:
            raise ValueError("at least one evidence document is required")
        if not profile_version.strip():
            raise ValueError("profile_version is required")
        if k1 <= 0 or not 0 <= b <= 1:
            raise ValueError("invalid BM25 parameters")
        ids = [document.evidence_id for document in docs]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence IDs must be unique")

        self.documents = docs
        self.profile_version = profile_version
        self.k1 = float(k1)
        self.b = float(b)
        self._by_id = {document.evidence_id: document for document in docs}
        self._tokens = {document.evidence_id: tokenize(document.text) for document in docs}
        self._term_counts = {
            evidence_id: Counter(tokens) for evidence_id, tokens in self._tokens.items()
        }
        self._lengths = {evidence_id: len(tokens) for evidence_id, tokens in self._tokens.items()}
        self._average_length = sum(self._lengths.values()) / len(self._lengths)
        self._document_frequency: Counter[str] = Counter()
        for tokens in self._tokens.values():
            self._document_frequency.update(set(tokens))

        canonical = [
            {
                "evidence_id": document.evidence_id,
                "text_hash": hashlib.sha256(document.text.encode("utf-8")).hexdigest(),
                "metadata": dict(document.metadata),
            }
            for document in sorted(docs, key=lambda item: item.evidence_id)
        ]
        corpus_hash = hashlib.sha256(
            json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        self.manifest = ProjectionManifest(
            profile_version=profile_version,
            evidence_ids=tuple(sorted(ids)),
            corpus_hash=corpus_hash,
        )

    def lexical_scores(self, query: str) -> dict[str, float]:
        terms = tokenize(query)
        if not terms:
            return {evidence_id: 0.0 for evidence_id in self._by_id}
        total_docs = len(self.documents)
        result: dict[str, float] = {}
        for evidence_id in self._by_id:
            score = 0.0
            counts = self._term_counts[evidence_id]
            length = self._lengths[evidence_id]
            for term in terms:
                frequency = counts.get(term, 0)
                if not frequency:
                    continue
                document_frequency = self._document_frequency[term]
                inverse_frequency = math.log(
                    1 + (total_docs - document_frequency + 0.5) / (document_frequency + 0.5)
                )
                denominator = frequency + self.k1 * (
                    1 - self.b + self.b * length / max(self._average_length, 1.0)
                )
                score += inverse_frequency * frequency * (self.k1 + 1) / denominator
            result[evidence_id] = score
        return result

    def search(
        self,
        query: str,
        *,
        semantic_scores: Mapping[str, float] | None = None,
        lexical_weight: float = 0.55,
        semantic_weight: float = 0.45,
        limit: int = 10,
    ) -> list[RetrievalResult]:
        if limit < 1:
            raise ValueError("limit must be positive")
        if lexical_weight < 0 or semantic_weight < 0 or lexical_weight + semantic_weight <= 0:
            raise ValueError("retrieval weights must be non-negative with a positive total")
        supplied = dict(semantic_scores or {})
        unknown = set(supplied) - set(self._by_id)
        if unknown:
            raise ValueError(f"semantic scores reference unknown evidence IDs: {sorted(unknown)}")
        for evidence_id, value in supplied.items():
            if not 0 <= float(value) <= 1:
                raise ValueError(f"semantic score for {evidence_id} must be in [0,1]")

        lexical = self.lexical_scores(query)
        maximum = max(lexical.values(), default=0.0)
        normalized = {
            evidence_id: (score / maximum if maximum > 0 else 0.0)
            for evidence_id, score in lexical.items()
        }
        weight_total = lexical_weight + semantic_weight
        results: list[RetrievalResult] = []
        for evidence_id, document in self._by_id.items():
            semantic = float(supplied[evidence_id]) if evidence_id in supplied else None
            effective_semantic = semantic if semantic is not None else 0.0
            combined = (
                lexical_weight * normalized[evidence_id] + semantic_weight * effective_semantic
            ) / weight_total
            results.append(
                RetrievalResult(
                    evidence_id=evidence_id,
                    lexical_score=normalized[evidence_id],
                    semantic_score=semantic,
                    combined_score=combined,
                    metadata=document.metadata,
                )
            )
        results.sort(key=lambda item: (-item.combined_score, item.evidence_id))
        return results[:limit]

