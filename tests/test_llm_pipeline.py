from __future__ import annotations

import hashlib
import unittest
from dataclasses import asdict

from market_aligner.domain.contracts import RawPosting
from market_aligner.llm.contracts import LLMReceipt, SemanticVacancyExtraction
from market_aligner.llm.pipeline import accept_extraction


class LLMPipelineTests(unittest.TestCase):
    def test_extraction_requires_matching_raw_and_output_hash_receipts(self) -> None:
        digest = hashlib.sha256(b"raw vacancy").hexdigest()
        raw = RawPosting(
            "board",
            "1",
            "https://example.test/1",
            "2026-08-01T00:00:00Z",
            raw_text="raw vacancy",
            content_sha256=digest,
        )
        extraction = SemanticVacancyExtraction(
            source_content_sha256=digest,
            title="Engineer",
            company="Example",
            location="Remote",
            description="Build complete production systems.",
            responsibilities=("Build systems",),
            required_skills=("Python",),
            preferred_skills=(),
            required_qualifications=(),
            preferred_qualifications=(),
            work_authorisation=(),
            contract_type="permanent",
            seniority="entry",
            remote_policy="remote",
            extraction_confidence=0.9,
        )
        receipt = LLMReceipt.bind(
            receipt_id="receipt-1",
            task="semantic_vacancy_extraction",
            model="model-version",
            prompt_version="prompt-v1",
            inputs={"source_content_sha256": digest},
            output=extraction,
            created_at="2026-08-01T00:00:00Z",
        )
        vacancy = accept_extraction(raw, extraction, receipt)
        self.assertEqual("Python", vacancy.required_skills[0])
        bad = LLMReceipt(**{**asdict(receipt), "output_sha256": hashlib.sha256(b"bad").hexdigest()})
        with self.assertRaisesRegex(ValueError, "output hash"):
            accept_extraction(raw, extraction, bad)


if __name__ == "__main__":
    unittest.main()
