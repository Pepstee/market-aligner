from __future__ import annotations

import unittest

from career_automation.retrieval import EvidenceDocument, HybridEvidenceIndex


class HybridEvidenceIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.documents = [
            EvidenceDocument("e-python", "Built Python API automation with deterministic tests"),
            EvidenceDocument("e-design", "Produced retail spatial design and visual concepts"),
            EvidenceDocument("e-cloud", "Deployed event driven systems using AWS Lambda"),
        ]

    def test_lexical_results_retain_canonical_evidence_ids(self) -> None:
        index = HybridEvidenceIndex(self.documents, profile_version="profile-v1")
        results = index.search("Python automation", limit=2)
        self.assertEqual(results[0].evidence_id, "e-python")
        self.assertGreater(results[0].lexical_score, results[1].lexical_score)
        self.assertEqual(index.manifest.evidence_ids, ("e-cloud", "e-design", "e-python"))

    def test_semantic_scores_can_be_hybridized_but_not_invent_ids(self) -> None:
        index = HybridEvidenceIndex(self.documents, profile_version="profile-v1")
        results = index.search(
            "platform engineering",
            semantic_scores={"e-cloud": 0.98, "e-python": 0.3},
            lexical_weight=0.2,
            semantic_weight=0.8,
        )
        self.assertEqual(results[0].evidence_id, "e-cloud")
        with self.assertRaisesRegex(ValueError, "unknown evidence IDs"):
            index.search("anything", semantic_scores={"fabricated": 0.9})

    def test_projection_hash_changes_when_canonical_text_changes(self) -> None:
        first = HybridEvidenceIndex(self.documents, profile_version="profile-v1")
        changed = list(self.documents)
        changed[0] = EvidenceDocument("e-python", "Different verified content")
        second = HybridEvidenceIndex(changed, profile_version="profile-v1")
        self.assertNotEqual(first.manifest.corpus_hash, second.manifest.corpus_hash)

    def test_invalid_documents_and_scores_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique"):
            HybridEvidenceIndex(
                [EvidenceDocument("same", "one"), EvidenceDocument("same", "two")],
                profile_version="v1",
            )
        index = HybridEvidenceIndex(self.documents, profile_version="v1")
        with self.assertRaisesRegex(ValueError, r"\[0,1\]"):
            index.search("x", semantic_scores={"e-python": 1.1})


if __name__ == "__main__":
    unittest.main()
