from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from typing import Any

from market_aligner.domain.contracts import RawPosting
from market_aligner.llm.codex_gateway import (
    CodexGatewayError,
    CodexSemanticGateway,
    SYNTHETIC_CANARY_MARKER,
    synthetic_extraction_canary,
)
from market_aligner.llm.contracts import LLMReceipt, SemanticVacancyExtraction
from market_aligner.llm.pipeline import accept_extraction


class FakeCodexRunner:
    def __init__(self, responses: list[dict[str, Any]], *, tool_item: str | None = None) -> None:
        self.responses = list(responses)
        self.tool_item = tool_item
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        response = self.responses.pop(0)
        output = Path(command[command.index("--output-last-message") + 1])
        output.write_text(json.dumps(response), encoding="utf-8")
        item_type = self.tool_item or "agent_message"
        events = (
            {"type": "thread.started", "thread_id": "synthetic-thread"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "1", "type": item_type}},
            {"type": "turn.completed", "usage": {}},
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="\n".join(json.dumps(event) for event in events),
            stderr="",
        )


def _extraction_payload(digest: str) -> dict[str, Any]:
    return {
        "source_content_sha256": digest,
        "title": "Junior Automation Engineer",
        "company": "Synthetic Example",
        "location": "Remote",
        "description": "Build Python automation with mentorship.",
        "responsibilities": ["Build automation"],
        "required_skills": ["Python"],
        "preferred_skills": [],
        "required_qualifications": [],
        "preferred_qualifications": [],
        "work_authorisation": [],
        "contract_type": "permanent",
        "seniority": "junior",
        "remote_policy": "remote",
        "extraction_confidence": 0.9,
        "unknown_fields": [],
    }


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

    def test_detached_codex_gateway_is_schema_and_transport_bound_without_ambient_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "codex"
            binary.write_bytes(b"synthetic codex binary")
            digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
            extraction_response = _extraction_payload(digest)
            alignment_response = {
                "profile_id": "prf_" + "a" * 32,
                "profile_version": "synthetic-v1",
                "job_key": "synthetic:1",
                "matches": [
                    {
                        "requirement": "Python",
                        "evidence_ids": ["ev-1"],
                        "strength": 0.9,
                        "rationale": "The supplied evidence explicitly names Python.",
                    }
                ],
                "missing_requirements": [],
                "technical_alignment": 0.8,
                "evidence_match": 0.9,
                "confidence": 0.9,
                "unknowns": [],
            }
            runner = FakeCodexRunner([extraction_response, alignment_response])
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={
                    "HOME": str(root),
                    "PATH": "/usr/bin",
                    "SECRET_TEST_VALUE": "must-not-cross-boundary",
                },
                runner=runner,
            )
            raw_context = {
                "board": "synthetic",
                "job_id": "1",
                "url": "https://example.invalid/1",
                "content_sha256": digest,
                "raw_text": "synthetic vacancy",
            }
            extraction, extraction_receipt = gateway.extract_vacancy(raw_context)
            alignment_context = {
                "profile": {
                    "profile_id": alignment_response["profile_id"],
                    "profile_version": "synthetic-v1",
                    "evidence_ledger": [{"evidence_id": "ev-1", "claim": "Python"}],
                },
                "track": "synthetic",
                "vacancy": {
                    "board": "synthetic",
                    "job_id": "1",
                    "required_skills": ["Python"],
                },
            }
            alignment, alignment_receipt = gateway.align_evidence(alignment_context)

            self.assertEqual("Junior Automation Engineer", extraction.title)
            self.assertEqual("synthetic:1", alignment.job_key)
            for receipt in (extraction_receipt, alignment_receipt):
                self.assertEqual("gpt-test-explicit", receipt.model)
                self.assertIsNotNone(receipt.transport)
                assert receipt.transport is not None
                self.assertEqual(1, receipt.transport.invocation_count)
                self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), receipt.transport.binary_sha256)
                self.assertEqual(64, len(receipt.transport.transport_sha256))
                self.assertEqual(receipt.receipt_id, receipt.transport.receipt_sha256)
            self.assertEqual(2, len(runner.calls))
            for command, call in runner.calls:
                self.assertIn("--ephemeral", command)
                self.assertIn("--ignore-user-config", command)
                self.assertIn("--ignore-rules", command)
                self.assertIn("project_doc_max_bytes=0", command)
                self.assertIn("project_doc_fallback_filenames=[]", command)
                self.assertIn("--output-schema", command)
                self.assertEqual("gpt-test-explicit", command[command.index("--model") + 1])
                self.assertNotIn("SECRET_TEST_VALUE", call["env"])
                self.assertTrue(Path(call["cwd"]).name.startswith("market-aligner-codex-request-"))

    def test_detached_codex_gateway_fails_closed_on_tool_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
            runner = FakeCodexRunner([_extraction_payload(digest)], tool_item="command_execution")
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={"HOME": temporary, "PATH": "/usr/bin"},
                runner=runner,
            )
            with self.assertRaisesRegex(CodexGatewayError, "forbidden tool item"):
                gateway.extract_vacancy({"content_sha256": digest, "raw_text": "synthetic vacancy"})

    def test_synthetic_canary_is_explicitly_marked_and_offline_in_test(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            text = (
                f"{SYNTHETIC_CANARY_MARKER}\nSynthetic Example Ltd seeks a junior automation "
                "engineer to build Python tests. Permanent remote role with mentorship and training."
            )
            runner = FakeCodexRunner([_extraction_payload(hashlib.sha256(text.encode()).hexdigest())])
            extraction, receipt = synthetic_extraction_canary(
                CodexSemanticGateway(
                    model="gpt-test-explicit",
                    codex_binary=str(binary),
                    environment={"HOME": temporary, "PATH": "/usr/bin"},
                    runner=runner,
                )
            )
            self.assertEqual("Junior Automation Engineer", extraction.title)
            self.assertIn(SYNTHETIC_CANARY_MARKER, runner.calls[0][1]["input"])
            self.assertIn('"synthetic_non_candidate_canary":true', runner.calls[0][1]["input"])
            self.assertIsNotNone(receipt.transport)

    @unittest.skipUnless(
        os.environ.get("MARKET_ALIGNER_LIVE_SYNTHETIC_CANARY") == "1",
        "explicit live synthetic canary only",
    )
    def test_live_synthetic_codex_canary(self) -> None:
        model = os.environ.get("MARKET_ALIGNER_CANARY_MODEL", "").strip()
        self.assertTrue(model, "MARKET_ALIGNER_CANARY_MODEL is required")
        extraction, receipt = synthetic_extraction_canary(CodexSemanticGateway(model=model))
        self.assertIn("Automation", extraction.title)
        self.assertEqual(SYNTHETIC_CANARY_MARKER, SYNTHETIC_CANARY_MARKER)
        self.assertIsNotNone(receipt.transport)


if __name__ == "__main__":
    unittest.main()
