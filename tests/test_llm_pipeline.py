from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import subprocess
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from market_aligner.domain.contracts import RawPosting
from market_aligner.applications.canonical import ContractValidationError
from market_aligner.collectors.evidence import bind_public_listing
from market_aligner.llm.codex_gateway import (
    CodexGatewayError,
    CodexSemanticGateway,
    EXTRACTION_PROMPT_VERSION,
    EXTRACTION_SCHEMA,
    VACANCY_ELIGIBILITY_PROMPT_VERSION,
    VACANCY_ELIGIBILITY_SCHEMA,
    SYNTHETIC_CANARY_MARKER,
    _PROMPTS,
    _DISABLED_CODE_MODE_HOST_NOTICE,
    _event_validation_policy_fields,
    _validate_events,
    synthetic_extraction_canary,
)
from market_aligner.llm.contracts import (
    LLMReceipt,
    SemanticVacancyExtraction,
    VACANCY_ELIGIBILITY_FIELDS,
    VACANCY_ELIGIBILITY_FACTS_VERSION,
    VacancyEligibilityEvidence,
    VacancyEligibilityFacts,
    canonical_hash,
)
from market_aligner.llm.pipeline import (
    accept_alignment,
    accept_extraction,
    accept_vacancy_eligibility_facts,
    quote_supports_eligibility,
    supports_can_sponsor_visas,
    supports_explicit_uk_work_clause,
    verified_eligibility_capture,
    vacancy_eligibility_input,
)
from market_aligner.llm.structured import (
    PROJECTION_FIELDS,
    align_approved_evidence,
    extract_structured_vacancy,
)
from market_aligner.profiler.schema import EvidenceItem
from market_aligner.state.vacancies import raw_posting_content_sha256


class FakeCodexRunner:
    def __init__(
        self, responses: list[dict[str, Any]], *, tool_item: str | None = None
    ) -> None:
        self.responses = list(responses)
        self.tool_item = tool_item
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.schemas: list[dict[str, Any]] = []

    def __call__(
        self, command: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        schema = Path(command[command.index("--output-schema") + 1])
        self.schemas.append(json.loads(schema.read_text(encoding="utf-8")))
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


def _alignment_payload() -> dict[str, Any]:
    return {
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


def _jsonl_events(*events: dict[str, Any]) -> str:
    return "\n".join(json.dumps(event) for event in events)


def _disabled_host_notice_event(event_type: str = "item.completed") -> dict[str, Any]:
    return {
        "type": event_type,
        "item": {
            "type": "error",
            "message": _DISABLED_CODE_MODE_HOST_NOTICE,
        },
    }


class LLMPipelineTests(unittest.TestCase):
    @staticmethod
    def _structured_listing() -> tuple[RawPosting, dict[str, str]]:
        values = {
            "company": "Example Ltd",
            "contract_type": "permanent",
            "description": "Build Python automation and operate reliable services.",
            "expires_at": "2026-09-30T00:00:00Z",
            "location": {
                "country_code": "GB",
                "locality": "London",
                "raw_text": "London, United Kingdom (hybrid)",
                "region": "England",
                "work_mode": "hybrid",
            },
            "minimum_years_experience": 2,
            "posted_at": "2026-08-30T00:00:00Z",
            "preferred_qualifications": [],
            "preferred_skills": ["Kubernetes"],
            "required_qualifications": ["Production engineering experience"],
            "required_residence": "GB",
            "required_skills": ["Python"],
            "requirements": ["Python", "Kubernetes"],
            "responsibilities": ["Build automation"],
            "seniority": "junior",
            "sponsorship_available": False,
            "title": "Automation Engineer",
            "work_authorisation": ["GB"],
        }
        exact = json.dumps({"job": values}, separators=(",", ":")).encode()
        digest = hashlib.sha256(exact).hexdigest()
        raw = RawPosting(
            "greenhouse",
            "structured-1",
            "https://example.test/jobs/structured-1",
            "2026-08-31T00:00:00Z",
            content_type="application/json",
            content_sha256=digest,
            public_content_base64=base64.b64encode(exact).decode(),
        )
        pointers = {name: f"/job/{name}" for name in PROJECTION_FIELDS}
        return raw, pointers

    def test_deterministic_structured_extraction_and_alignment_are_receipt_bound(
        self,
    ) -> None:
        raw, pointers = self._structured_listing()
        facts = extract_structured_vacancy(
            raw,
            pointers,
            receipt_inputs={"content_sha256": raw.content_sha256},
        )
        vacancy = accept_extraction(raw, facts.extraction, facts.extraction_receipt)
        self.assertEqual(
            canonical_hash(
                {
                    "caller_inputs": {"content_sha256": raw.content_sha256},
                    "pointers": {
                        name: pointers[name] for name in sorted(PROJECTION_FIELDS)
                    },
                    "source_content_sha256": raw.content_sha256,
                    "source_url": raw.url,
                }
            ),
            facts.extraction_receipt.input_sha256,
        )
        self.assertEqual("GB", facts.location.country_code)
        self.assertEqual("hybrid", vacancy.remote_policy)
        self.assertEqual(2.0, facts.minimum_years_experience)
        self.assertEqual(("GB",), vacancy.work_authorisation)

        evidence = {
            "ev-python": EvidenceItem(
                evidence_id="ev-python",
                kind="project",
                claim="Built Python automation for production systems.",
                source_ref="portfolio:automation",
                status="verified",
                confidence=0.9,
                content_sha256="a" * 64,
            )
        }
        alignment, receipt = align_approved_evidence(
            profile_id="prf_" + "b" * 32,
            profile_version="profile-v1",
            job_key=raw.key,
            requirements=facts.requirements,
            evidence=evidence,
            selected_evidence_ids=("ev-python",),
            receipt_inputs={"evidence_ids": ["ev-python"]},
            created_at="2026-08-31T00:00:00Z",
        )
        accepted = accept_alignment(alignment, evidence, receipt)
        self.assertEqual(
            canonical_hash(
                {
                    "caller_inputs": {"evidence_ids": ["ev-python"]},
                    "job_key": raw.key,
                    "profile_id": "prf_" + "b" * 32,
                    "profile_version": "profile-v1",
                    "requirements": list(facts.requirements),
                    "selected_evidence": [asdict(evidence["ev-python"])],
                }
            ),
            receipt.input_sha256,
        )
        self.assertEqual(("Kubernetes",), accepted.missing_requirements)
        self.assertEqual(("ev-python",), accepted.matches[0].evidence_ids)
        self.assertEqual(0.5, accepted.evidence_match)

    def test_structured_extraction_rejects_digest_and_json_ambiguity(self) -> None:
        raw, pointers = self._structured_listing()
        bad_digest = RawPosting(**{**asdict(raw), "content_sha256": "0" * 64})
        with self.assertRaisesRegex(ValueError, "digest differs"):
            extract_structured_vacancy(
                bad_digest,
                pointers,
                receipt_inputs={"content_sha256": bad_digest.content_sha256},
            )

        duplicate = b'{"job":{},"job":{}}'
        ambiguous = RawPosting(
            raw.board,
            raw.job_id,
            raw.url,
            raw.fetched_at,
            content_sha256=hashlib.sha256(duplicate).hexdigest(),
            public_content_base64=base64.b64encode(duplicate).decode(),
        )
        with self.assertRaisesRegex(ValueError, "duplicate public-listing JSON key"):
            extract_structured_vacancy(
                ambiguous,
                pointers,
                receipt_inputs={"content_sha256": ambiguous.content_sha256},
            )

    def test_structured_alignment_rejects_unknown_or_duplicate_evidence_selection(
        self,
    ) -> None:
        evidence = {
            "ev-python": EvidenceItem(
                evidence_id="ev-python",
                kind="project",
                claim="Python",
                source_ref="portfolio:automation",
                status="verified",
                confidence=1.0,
                content_sha256="b" * 64,
            )
        }
        arguments = {
            "profile_id": "prf_" + "c" * 32,
            "profile_version": "profile-v1",
            "job_key": "greenhouse:structured-1",
            "requirements": ("Python",),
            "evidence": evidence,
            "receipt_inputs": {"evidence_ids": ["ev-python"]},
            "created_at": "2026-08-31T00:00:00Z",
        }
        with self.assertRaisesRegex(ValueError, "unknown"):
            align_approved_evidence(
                **arguments,
                selected_evidence_ids=("ev-missing",),
            )
        with self.assertRaisesRegex(ValueError, "unique"):
            align_approved_evidence(
                **arguments,
                selected_evidence_ids=("ev-python", "ev-python"),
            )

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
        bad = LLMReceipt(
            **{**asdict(receipt), "output_sha256": hashlib.sha256(b"bad").hexdigest()}
        )
        with self.assertRaisesRegex(ValueError, "output hash"):
            accept_extraction(raw, extraction, bad)

    def test_gateway_canonicalizes_work_authorisation_and_binds_both_hashes(
        self,
    ) -> None:
        digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            results = []
            for codes in (["US", "GB", "US"], ["GB", "US"]):
                response = _extraction_payload(digest)
                response["work_authorisation"] = codes
                response["unknown_fields"] = ["authorization wording is ambiguous"]
                runner = FakeCodexRunner([response])
                gateway = CodexSemanticGateway(
                    model="gpt-test-explicit",
                    codex_binary=str(binary),
                    environment={"HOME": temporary, "PATH": "/usr/bin"},
                    runner=runner,
                )
                extraction, receipt = gateway.extract_vacancy(
                    {
                        "board": "synthetic",
                        "job_id": "1",
                        "url": "https://example.invalid/1",
                        "content_sha256": digest,
                        "raw_text": "synthetic vacancy",
                    }
                )
                self.assertEqual(("GB", "US"), extraction.work_authorisation)
                self.assertEqual(
                    ("authorization wording is ambiguous",), extraction.unknown_fields
                )
                self.assertEqual(1, len(runner.calls))
                self.assertEqual(
                    hashlib.sha256(json.dumps(response).encode("utf-8")).hexdigest(),
                    receipt.transport.response_sha256,
                )
                self.assertIn(EXTRACTION_PROMPT_VERSION, runner.calls[0][1]["input"])
                self.assertIn(
                    "Never list applicant entitlements", runner.calls[0][1]["input"]
                )
                property_schema = runner.schemas[0]["properties"]["work_authorisation"]
                self.assertEqual("^[A-Z]{2}$", property_schema["items"]["pattern"])
                self.assertNotIn("uniqueItems", property_schema)
                self.assertIn("work_authorisation", runner.schemas[0]["required"])
                self.assertEqual(EXTRACTION_PROMPT_VERSION, receipt.prompt_version)
                results.append(receipt)
            self.assertEqual(results[0].output_sha256, results[1].output_sha256)
            self.assertNotEqual(
                results[0].transport.response_sha256,
                results[1].transport.response_sha256,
            )

        empty_response = _extraction_payload(digest)
        empty_response["unknown_fields"] = ["work eligibility scope is unclear"]
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            runner = FakeCodexRunner([empty_response])
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={"HOME": temporary, "PATH": "/usr/bin"},
                runner=runner,
            )
            extraction, _ = gateway.extract_vacancy(
                {"content_sha256": digest, "raw_text": "synthetic vacancy"}
            )
            self.assertEqual((), extraction.work_authorisation)
            self.assertEqual(
                ("work eligibility scope is unclear",), extraction.unknown_fields
            )

    def test_gateway_rejects_malformed_work_authorisation_without_retry_or_echo(
        self,
    ) -> None:
        digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
        malformed_values = (
            None,
            "US",
            "US,GB",
            {},
            True,
            0,
            ["US", None],
            ["US", 1],
            ["us"],
            ["Us"],
            ["USA"],
            [" US"],
            ["US "],
            ["United States"],
            ["ＵＳ"],
            ["applicant must hold work rights in Germany"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            for malformed in malformed_values:
                response = _extraction_payload(digest)
                response["work_authorisation"] = malformed
                runner = FakeCodexRunner([response])
                gateway = CodexSemanticGateway(
                    model="gpt-test-explicit",
                    codex_binary=str(binary),
                    environment={"HOME": temporary, "PATH": "/usr/bin"},
                    runner=runner,
                )
                with self.subTest(malformed=malformed):
                    with self.assertRaisesRegex(
                        CodexGatewayError,
                        "work_authorisation must be sorted unique uppercase two-letter country codes",
                    ) as raised:
                        gateway.extract_vacancy(
                            {"content_sha256": digest, "raw_text": "synthetic vacancy"}
                        )
                    self.assertNotIn(repr(malformed), str(raised.exception))
                    self.assertEqual(1, len(runner.calls))

            response = _extraction_payload(digest)
            del response["work_authorisation"]
            runner = FakeCodexRunner([response])
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={"HOME": temporary, "PATH": "/usr/bin"},
                runner=runner,
            )
            with self.assertRaisesRegex(
                CodexGatewayError,
                "work_authorisation must be sorted unique uppercase two-letter country codes",
            ):
                gateway.extract_vacancy(
                    {"content_sha256": digest, "raw_text": "synthetic vacancy"}
                )
            self.assertEqual(1, len(runner.calls))

    def test_gateway_extracts_source_bound_vacancy_eligibility_once(self) -> None:
        digest = hashlib.sha256(b"synthetic vacancy eligibility").hexdigest()
        response = {
            "source_content_sha256": digest,
            "work_jurisdiction": None,
            "required_residence": None,
            "sponsorship_available": None,
            "minimum_years_experience": 0,
            "contract_type": None,
            "source_evidence": [
                {
                    "field": "minimum_years_experience",
                    "quote": "Minimum 0 years of experience.",
                }
            ],
            "unknown_fields": [
                "contract_type",
                "required_residence",
                "sponsorship_available",
                "work_jurisdiction",
            ],
        }
        inputs = {
            "content_sha256": digest,
            "raw_text": "Minimum 0 years of experience.",
        }
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            runner = FakeCodexRunner([response])
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={"HOME": temporary, "PATH": "/usr/bin"},
                runner=runner,
            )
            facts, receipt = gateway.extract_vacancy_eligibility(inputs)

        self.assertEqual(0, facts.minimum_years_experience)
        self.assertEqual("minimum_years_experience", facts.source_evidence[0].field)
        self.assertEqual(1, len(runner.calls))
        self.assertEqual(VACANCY_ELIGIBILITY_PROMPT_VERSION, receipt.prompt_version)
        self.assertTrue(VACANCY_ELIGIBILITY_PROMPT_VERSION.endswith(".codex.v2"))
        self.assertIn(
            "distributed working within the UK",
            _PROMPTS["vacancy_eligibility_facts"],
        )
        self.assertIn(
            "Leave required_residence null",
            _PROMPTS["vacancy_eligibility_facts"],
        )
        self.assertEqual("vacancy_eligibility_facts", receipt.task)
        self.assertEqual(
            VACANCY_ELIGIBILITY_SCHEMA,
            runner.schemas[0],
        )
        self.assertIn("alphabetical field order", runner.calls[0][1]["input"])
        self.assertEqual(
            hashlib.sha256(json.dumps(response).encode("utf-8")).hexdigest(),
            receipt.transport.response_sha256,
        )

    def test_detached_codex_gateway_is_schema_and_transport_bound_without_ambient_context(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "codex"
            binary.write_bytes(b"synthetic codex binary")
            digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
            extraction_response = _extraction_payload(digest)
            profile_id = "prf_" + "a" * 32
            alignment_response = _alignment_payload()
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
                    "profile_id": profile_id,
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
            self.assertEqual(profile_id, alignment.profile_id)
            self.assertEqual("synthetic-v1", alignment.profile_version)
            self.assertEqual(
                hashlib.sha256(json.dumps(alignment_response).encode()).hexdigest(),
                alignment_receipt.transport.response_sha256,
            )
            self.assertEqual(
                hashlib.sha256(
                    json.dumps(
                        asdict(alignment), sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest(),
                alignment_receipt.output_sha256,
            )
            self.assertNotIn("profile_id", runner.schemas[1]["properties"])
            self.assertNotIn("profile_version", runner.schemas[1]["properties"])
            self.assertNotIn("job_key", runner.schemas[1]["properties"])
            self.assertFalse(runner.schemas[1]["additionalProperties"])
            for receipt in (extraction_receipt, alignment_receipt):
                self.assertEqual("gpt-test-explicit", receipt.model)
                self.assertIsNotNone(receipt.transport)
                assert receipt.transport is not None
                self.assertEqual(1, receipt.transport.invocation_count)
                self.assertEqual(
                    hashlib.sha256(binary.read_bytes()).hexdigest(),
                    receipt.transport.binary_sha256,
                )
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
                self.assertEqual(
                    "gpt-test-explicit", command[command.index("--model") + 1]
                )
                self.assertNotIn("SECRET_TEST_VALUE", call["env"])
                self.assertTrue(
                    Path(call["cwd"]).name.startswith("market-aligner-codex-request-")
                )

    def test_alignment_rejects_realistic_model_authority_echo_after_one_call(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            response = {
                **_alignment_payload(),
                "profile_id": "candidate-profile",
                "profile_version": "wrong-version",
                "job_key": "workable:wrong-job",
            }
            runner = FakeCodexRunner([response])
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={"HOME": temporary, "PATH": "/usr/bin"},
                runner=runner,
            )
            context = {
                "profile": {
                    "profile_id": "prf_" + "b" * 32,
                    "profile_version": "canonical-v1",
                    "evidence_ledger": [{"evidence_id": "ev-1", "claim": "Python"}],
                },
                "track": "automation",
                "vacancy": {"board": "workable", "job_id": "real-job"},
            }
            with self.assertRaisesRegex(
                CodexGatewayError, "forbidden authority fields"
            ):
                gateway.align_evidence(context)
            self.assertEqual(1, len(runner.calls))

    def test_detached_codex_gateway_fails_closed_on_tool_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
            runner = FakeCodexRunner(
                [_extraction_payload(digest)], tool_item="command_execution"
            )
            gateway = CodexSemanticGateway(
                model="gpt-test-explicit",
                codex_binary=str(binary),
                environment={"HOME": temporary, "PATH": "/usr/bin"},
                runner=runner,
            )
            with self.assertRaisesRegex(CodexGatewayError, "forbidden tool item") as error:
                gateway.extract_vacancy(
                    {"content_sha256": digest, "raw_text": "synthetic vacancy"}
                )
            self.assertEqual("codex attempted forbidden tool item", str(error.exception))

    def test_disabled_code_mode_notice_is_exact_opt_in_and_pre_turn_only(self) -> None:
        notice = _disabled_host_notice_event()
        valid = _jsonl_events(
            {"type": "thread.started"},
            notice,
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "agent_message"}},
            {"type": "turn.completed"},
        )
        with self.assertRaisesRegex(CodexGatewayError, "rejected an error item"):
            _validate_events(valid)
        _validate_events(valid, allow_disabled_host_notice=True)

        policy = _event_validation_policy_fields(True)
        self.assertEqual(
            "codex-disabled-code-mode-host-preturn-notice-v1",
            policy["event_validation_policy"],
        )
        self.assertIs(policy["allow_disabled_host_notice"], True)
        self.assertIs(
            _event_validation_policy_fields(False)["allow_disabled_host_notice"],
            False,
        )
        self.assertNotEqual(
            canonical_hash({"transport": {}, **_event_validation_policy_fields(True)}),
            canonical_hash({"transport": {}, **_event_validation_policy_fields(False)}),
        )

    def test_disabled_code_mode_notice_rejects_late_changed_repeated_and_misplaced_events(
        self,
    ) -> None:
        notice = _disabled_host_notice_event()
        invalid_streams = (
            _jsonl_events(
                {"type": "thread.started"},
                {"type": "turn.started"},
                notice,
                {"type": "turn.completed"},
            ),
            _jsonl_events(
                {"type": "thread.started"},
                {"type": "unknown.metadata"},
                notice,
                {"type": "turn.completed"},
            ),
            _jsonl_events(
                {"type": "thread.started"},
                {"type": "turn.started"},
                {"type": "turn.completed"},
                notice,
            ),
            _jsonl_events(
                {"type": "thread.started"},
                {"type": "item.completed", "item": {"type": "error", "message": "changed"}},
                {"type": "turn.completed"},
            ),
            _jsonl_events(
                {"type": "thread.started"},
                notice,
                notice,
                {"type": "turn.completed"},
            ),
            _jsonl_events(
                {"type": "thread.started"},
                _disabled_host_notice_event("item.started"),
                {"type": "turn.completed"},
            ),
        )
        for stream in invalid_streams:
            with self.subTest(stream=stream), self.assertRaises(CodexGatewayError):
                _validate_events(stream, allow_disabled_host_notice=True)

    def test_disabled_code_mode_notice_never_allows_tool_items(self) -> None:
        for event_type in (
            "item.started",
            "item.updated",
            "item.completed",
            "unknown.metadata",
            "thread.started",
        ):
            with self.subTest(event_type=event_type):
                stream = _jsonl_events(
                    {
                        "type": event_type,
                        "item": {"type": "command_execution", "command": "blocked"},
                    },
                    {"type": "turn.completed"},
                )
                with self.assertRaisesRegex(CodexGatewayError, "forbidden tool item"):
                    _validate_events(stream, allow_disabled_host_notice=True)

        malformed_item = _jsonl_events(
            {"type": "item.started", "item": []},
            {"type": "turn.completed"},
        )
        with self.assertRaisesRegex(CodexGatewayError, "invalid item"):
            _validate_events(malformed_item, allow_disabled_host_notice=True)

    def test_synthetic_canary_is_explicitly_marked_and_offline_in_test(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_bytes(b"synthetic codex binary")
            text = (
                f"{SYNTHETIC_CANARY_MARKER}\nSynthetic Example Ltd seeks a junior automation "
                "engineer to build Python tests. Permanent remote role with mentorship and training."
            )
            runner = FakeCodexRunner(
                [_extraction_payload(hashlib.sha256(text.encode()).hexdigest())]
            )
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
            self.assertIn(
                '"synthetic_non_candidate_canary":true', runner.calls[0][1]["input"]
            )
            self.assertIsNotNone(receipt.transport)

    @unittest.skipUnless(
        os.environ.get("MARKET_ALIGNER_LIVE_SYNTHETIC_CANARY") == "1",
        "explicit live synthetic canary only",
    )
    def test_live_synthetic_codex_canary(self) -> None:
        model = os.environ.get("MARKET_ALIGNER_CANARY_MODEL", "").strip()
        self.assertTrue(model, "MARKET_ALIGNER_CANARY_MODEL is required")
        extraction, receipt = synthetic_extraction_canary(
            CodexSemanticGateway(model=model)
        )
        self.assertIn("Automation", extraction.title)
        self.assertEqual(SYNTHETIC_CANARY_MARKER, SYNTHETIC_CANARY_MARKER)
        self.assertIsNotNone(receipt.transport)


if __name__ == "__main__":
    unittest.main()


class RetainedContractValidationTests(unittest.TestCase):
    def test_extraction_and_receipt_reject_donor_invalid_values(self) -> None:
        from dataclasses import replace
        from market_aligner.llm.contracts import _unit

        payload = _extraction_payload('a' * 64)
        for key, value in tuple(payload.items()):
            if isinstance(value, list):
                payload[key] = tuple(value)
        value = SemanticVacancyExtraction(**payload)
        for changes in (
            {'extraction_confidence': True},
            {'extraction_confidence': '0.5'},
            {'source_content_sha256': 'Z' * 64},
            {'required_skills': ['Python']},
            {'work_authorisation': ('gb',)},
            {'work_authorisation': ('GB', 'GB')},
        ):
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                replace(value, **changes)
        for bad in (float('nan'), float('inf'), -0.1, 1.1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _unit(bad, 'confidence')
        receipt = LLMReceipt.bind(
            receipt_id='synthetic', task='extraction', model='fixture-model',
            prompt_version='v1', inputs={'source': 'synthetic'},
            output=value, created_at='2026-09-14T00:00:00Z',
        )
        for changes in ({'model': ''}, {'input_sha256': 'x' * 64}, {'contract_version': 'invalid'}):
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                replace(receipt, **changes)


class RetainedSubjectBindingTests(unittest.TestCase):
    def test_exact_subject_receipts_reject_cross_job_and_requirement_results(self) -> None:
        from dataclasses import replace
        from market_aligner.llm.pipeline import (
            EvidenceAlignmentSubject, alignment_input, extraction_input,
            accept_subject_bound_alignment, accept_subject_bound_extraction,
        )
        from market_aligner.llm.contracts import EvidenceAlignment, EvidenceMatch

        raw, _ = LLMPipelineTests._structured_listing()
        payload = _extraction_payload(raw.content_sha256)
        payload = {key: tuple(value) if isinstance(value, list) else value for key, value in payload.items()}
        extraction = SemanticVacancyExtraction(**payload)
        receipt = LLMReceipt.bind(
            receipt_id='synthetic-extraction', task='semantic_vacancy_extraction',
            model='fixture-model', prompt_version='v1', inputs=extraction_input(raw),
            output=extraction, created_at='2026-09-14T00:00:00Z',
        )
        accept_subject_bound_extraction(raw, extraction, receipt)
        with self.assertRaisesRegex(ValueError, 'input identity differs'):
            accept_subject_bound_extraction(replace(raw, job_id='other'), extraction, receipt)
        subject = EvidenceAlignmentSubject(
            profile_id='prf_' + 'a' * 32, profile_version='v1',
            candidate_intent_sha256='b' * 64, role_track_id='engineering',
            job_key=raw.key, vacancy_snapshot_sha256='c' * 64,
            requirements_sha256='c' * 64, evidence_ledger_sha256='c' * 64,
            extraction_output_sha256='c' * 64, extraction_receipt_sha256='c' * 64,
        )
        item = EvidenceItem('ev-1', 'project', 'Python', 'synthetic:project', 'verified', 1.0, content_sha256='d' * 64)
        evidence = {'ev-1': item}
        alignment = EvidenceAlignment(
            subject.profile_id, subject.profile_version, subject.job_key,
            (EvidenceMatch('Python', ('ev-1',), 0.9, 'Direct evidence'),),
            (), 0.9, 0.9, 0.9,
        )
        inputs = alignment_input(subject, requirements=('Python',), evidence=evidence, selected_evidence_ids=('ev-1',))
        def bind(value):
            return LLMReceipt.bind(receipt_id='synthetic-alignment', task='evidence_alignment', model='fixture-model', prompt_version='v1', inputs=inputs, output=value, created_at='2026-09-14T00:00:00Z')
        arguments = dict(subject=subject, requirements=('Python',), selected_evidence_ids=('ev-1',))
        self.assertEqual(accept_subject_bound_alignment(alignment, evidence, bind(alignment), **arguments), alignment)
        for changed in (
            replace(alignment, job_key='another-job'),
            replace(alignment, missing_requirements=('Invented',)),
            replace(alignment, matches=(replace(alignment.matches[0], requirement='Invented'),)),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                accept_subject_bound_alignment(changed, evidence, bind(changed), **arguments)


class VacancyEligibilityContractTests(unittest.TestCase):
    fields = tuple(sorted(VACANCY_ELIGIBILITY_FIELDS))
    digest = "a" * 64
    _default_offices = object()

    def evidence(self, field: str) -> VacancyEligibilityEvidence:
        return VacancyEligibilityEvidence(field=field, quote="source quote")

    def build(
        self,
        overrides: dict[str, Any] | None = None,
        *,
        evidence: tuple[Any, ...] | None = None,
        digest: str = digest,
        version: str = "market-aligner.llm.v1",
    ) -> VacancyEligibilityFacts:
        values = dict.fromkeys(self.fields)
        values.update(overrides or {})
        if evidence is None:
            evidence = tuple(
                self.evidence(field)
                for field in self.fields
                if values[field] is not None
            )
        return VacancyEligibilityFacts(
            source_content_sha256=digest,
            work_jurisdiction=values["work_jurisdiction"],
            required_residence=values["required_residence"],
            sponsorship_available=values["sponsorship_available"],
            minimum_years_experience=values["minimum_years_experience"],
            contract_type=values["contract_type"],
            source_evidence=evidence,
            unknown_fields=tuple(
                field for field in self.fields if values[field] is None
            ),
            contract_version=version,
        )

    def test_all_unknown_and_false_zero_preserve_exact_support_sets(self) -> None:
        empty = self.build()
        self.assertEqual(self.fields, empty.unknown_fields)
        self.assertEqual((), empty.source_evidence)

        facts = self.build(
            {"sponsorship_available": False, "minimum_years_experience": 0}
        )
        self.assertIs(facts.sponsorship_available, False)
        self.assertEqual(0, facts.minimum_years_experience)
        self.assertNotIsInstance(facts.minimum_years_experience, bool)
        self.assertEqual(
            ("minimum_years_experience", "sponsorship_available"),
            tuple(item.field for item in facts.source_evidence),
        )
        self.assertEqual(
            ("contract_type", "required_residence", "work_jurisdiction"),
            facts.unknown_fields,
        )
        self.assertEqual(VACANCY_ELIGIBILITY_FACTS_VERSION, "market-aligner.vacancy-eligibility-facts.v1")

    def test_malformed_years_and_sponsorship_types_refuse(self) -> None:
        for years in (True, False, -1, -0.5, math.inf, -math.inf, math.nan, "3"):
            with self.subTest(years=years), self.assertRaises((TypeError, ValueError)):
                self.build({"minimum_years_experience": years})
        for sponsorship in (0, 1, 0.0, 1.0, "true"):
            with self.subTest(sponsorship=sponsorship), self.assertRaises(
                (TypeError, ValueError)
            ):
                self.build({"sponsorship_available": sponsorship})

    def test_evidence_and_contract_values_must_be_exact(self) -> None:
        invalid_evidence = (
            (),
            (self.evidence("work_jurisdiction"), self.evidence("work_jurisdiction")),
            lambda: (self.evidence("salary"),),
            ({"field": "work_jurisdiction", "quote": "source quote"},),
            (self.evidence("required_residence"),),
        )
        for value in invalid_evidence:
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                evidence = value() if callable(value) else value
                self.build({"work_jurisdiction": "US"}, evidence=evidence)
        for contract_type in ("Permanent", "permanent ", "unknown"):
            with self.subTest(contract_type=contract_type), self.assertRaises(ValueError):
                self.build({"contract_type": contract_type})
        with self.assertRaises(ValueError):
            VacancyEligibilityEvidence(field="salary", quote="source quote")

    def test_source_digest_and_contract_version_are_bound(self) -> None:
        for digest, version in (
            ("A" * 64, "market-aligner.llm.v1"),
            ("a" * 63, "market-aligner.llm.v1"),
            ("g" * 64, "market-aligner.llm.v1"),
            (self.digest, "market-aligner.llm.v2"),
            (self.digest, ""),
        ):
            with self.subTest(digest=digest, version=version), self.assertRaises(
                (TypeError, ValueError)
            ):
                self.build(digest=digest, version=version)

    def test_quote_support_uses_only_anchored_positive_and_negative_forms(self) -> None:
        cases = (
            ("sponsorship_available", True, "Visa sponsorship is available.", True),
            ("sponsorship_available", True, "We offer visa sponsorship.", True),
            ("sponsorship_available", True, "We sponsor visas", True),
            ("sponsorship_available", True, "We sponsor visas.", True),
            ("sponsorship_available", True, "We sponsor visas!", True),
            ("sponsorship_available", True, "We do sponsor visas", True),
            ("sponsorship_available", True, "We do sponsor visas.", True),
            ("sponsorship_available", True, "We do sponsor visas!", True),
            ("sponsorship_available", False, "Visa sponsorship is not available.", True),
            ("sponsorship_available", False, "We do not sponsor visas", True),
            ("sponsorship_available", True, "We do not sponsor visas.", False),
            ("sponsorship_available", True, "We may sponsor visas.", False),
            (
                "sponsorship_available",
                True,
                "We sponsor visas for some roles only.",
                False,
            ),
            ("sponsorship_available", True, "We do sponsor visas?", False),
            ("sponsorship_available", True, "We do sponsor visas!!", False),
            ("sponsorship_available", True, "Sponsorship is available.", False),
            ("sponsorship_available", True, "Sponsorship may be available.", False),
            (
                "sponsorship_available",
                True,
                "Visa sponsorship is available, but we do not sponsor visas.",
                False,
            ),
            (
                "minimum_years_experience",
                5,
                "Five is not a requirement: 5 years of experience is preferred, but no minimum experience is required.",
                False,
            ),
            (
                "minimum_years_experience",
                5,
                "Applicants must have at most 5 years of experience.",
                False,
            ),
            (
                "minimum_years_experience",
                0,
                "Minimum 0 years of experience.",
                True,
            ),
            (
                "minimum_years_experience",
                2.5,
                "A minimum of 2.5 years of experience is required.",
                True,
            ),
            (
                "minimum_years_experience",
                5,
                "At least 2 years of experience are required.",
                False,
            ),
            ("minimum_years_experience", True, "Minimum 1 years of experience.", False),
            (
                "minimum_years_experience",
                10**1000,
                "Minimum 0 years of experience.",
                False,
            ),
            ("contract_type", "permanent", "This is a permanent position.", True),
            ("contract_type", "permanent", "This is not a permanent position.", False),
            ("contract_type", "permanent", "This is a permanent role.", False),
            ("contract_type", "full_time", "This is a full-time role.", True),
            ("contract_type", "fixed_term", "This is a fixed-term contract.", False),
            ("salary_expectation", 100000, "This is a permanent position.", False),
            ("contract_type", "permanent", None, False),
        )
        for field, value, quote, expected in cases:
            with self.subTest(field=field, value=value, quote=quote):
                self.assertEqual(expected, quote_supports_eligibility(field, value, quote))

    def test_acceptance_binds_fact_quote_to_exact_public_source_and_receipt(self) -> None:
        raw, _ = LLMPipelineTests._structured_listing()
        raw = RawPosting(
            board=raw.board,
            job_id=raw.job_id,
            url=raw.url,
            fetched_at=raw.fetched_at,
            raw_json={
                "description": (
                    "This is a permanent position. "
                    "This is not a permanent position."
                )
            },
        )
        raw = replace(raw, content_sha256=raw_posting_content_sha256(raw))
        inputs = vacancy_eligibility_input(raw)
        facts = VacancyEligibilityFacts(
            source_content_sha256=str(inputs["content_sha256"]),
            work_jurisdiction=None,
            required_residence=None,
            sponsorship_available=None,
            minimum_years_experience=None,
            contract_type="permanent",
            source_evidence=(
                VacancyEligibilityEvidence(
                    field="contract_type", quote="This is a permanent position."
                ),
            ),
            unknown_fields=(
                "minimum_years_experience",
                "required_residence",
                "sponsorship_available",
                "work_jurisdiction",
            ),
        )
        receipt = LLMReceipt.bind(
            receipt_id="eligibility-receipt",
            task="vacancy_eligibility_facts",
            model="fixture-model",
            prompt_version="fixture-v1",
            inputs=inputs,
            output=facts,
            created_at="2026-10-06T00:00:00Z",
        )
        self.assertEqual(
            facts,
            accept_vacancy_eligibility_facts(
                raw, facts, receipt, inputs=inputs
            ),
        )
        self.assertEqual(raw.content_sha256, inputs["content_sha256"])
        self.assertEqual(64, len(inputs["public_capture_sha256"]))

        unsupported = VacancyEligibilityFacts(
            **{
                **asdict(facts),
                "source_evidence": (
                    VacancyEligibilityEvidence(
                        field="contract_type", quote="This is not a permanent position."
                    ),
                ),
            }
        )
        unsupported_receipt = LLMReceipt.bind(
            receipt_id="unsupported-eligibility-receipt",
            task="vacancy_eligibility_facts",
            model="fixture-model",
            prompt_version="fixture-v1",
            inputs=inputs,
            output=unsupported,
            created_at="2026-10-06T00:00:00Z",
        )
        with self.assertRaisesRegex(
            ContractValidationError, "exact quote grammar"
        ):
            accept_vacancy_eligibility_facts(
                raw, unsupported, unsupported_receipt, inputs=inputs
            )

    def test_sponsorship_quote_acceptance_requires_exact_source_membership(self) -> None:
        quote = "We do sponsor visas!"

        def bound_case(description: str) -> tuple[
            RawPosting, VacancyEligibilityFacts, LLMReceipt, dict[str, Any]
        ]:
            raw, _ = LLMPipelineTests._structured_listing()
            raw = RawPosting(
                board=raw.board,
                job_id=raw.job_id,
                url=raw.url,
                fetched_at=raw.fetched_at,
                raw_json={"description": description},
            )
            raw = replace(raw, content_sha256=raw_posting_content_sha256(raw))
            inputs = vacancy_eligibility_input(raw)
            facts = VacancyEligibilityFacts(
                source_content_sha256=str(inputs["content_sha256"]),
                work_jurisdiction=None,
                required_residence=None,
                sponsorship_available=True,
                minimum_years_experience=None,
                contract_type=None,
                source_evidence=(
                    VacancyEligibilityEvidence(
                        field="sponsorship_available", quote=quote
                    ),
                ),
                unknown_fields=(
                    "contract_type",
                    "minimum_years_experience",
                    "required_residence",
                    "work_jurisdiction",
                ),
            )
            receipt = LLMReceipt.bind(
                receipt_id="sponsorship-eligibility-receipt",
                task="vacancy_eligibility_facts",
                model="fixture-model",
                prompt_version="fixture-v1",
                inputs=inputs,
                output=facts,
                created_at="2026-10-06T00:00:00Z",
            )
            return raw, facts, receipt, inputs

        raw, facts, receipt, inputs = bound_case(
            "Anthropic is an equal opportunity employer. " + quote
        )
        self.assertEqual(
            facts,
            accept_vacancy_eligibility_facts(raw, facts, receipt, inputs=inputs),
        )

        absent_raw, absent_facts, absent_receipt, absent_inputs = bound_case(
            "Anthropic is an equal opportunity employer. We sponsor visas!"
        )
        with self.assertRaisesRegex(
            ContractValidationError, "absent from exact public content"
        ):
            accept_vacancy_eligibility_facts(
                absent_raw,
                absent_facts,
                absent_receipt,
                inputs=absent_inputs,
            )

    def test_can_sponsor_visas_support_is_exact_and_source_bound(self) -> None:
        def bound_case(
            quote: str, *, value: bool = True
        ) -> tuple[RawPosting, VacancyEligibilityFacts, LLMReceipt, dict[str, Any]]:
            raw, _ = LLMPipelineTests._structured_listing()
            raw = RawPosting(
                board=raw.board,
                job_id=raw.job_id,
                url=raw.url,
                fetched_at=raw.fetched_at,
                raw_json={"description": quote},
            )
            raw = replace(raw, content_sha256=raw_posting_content_sha256(raw))
            inputs = vacancy_eligibility_input(raw)
            facts = VacancyEligibilityFacts(
                source_content_sha256=str(inputs["content_sha256"]),
                work_jurisdiction=None,
                required_residence=None,
                sponsorship_available=value,
                minimum_years_experience=None,
                contract_type=None,
                source_evidence=(
                    VacancyEligibilityEvidence(
                        field="sponsorship_available", quote=quote
                    ),
                ),
                unknown_fields=(
                    "contract_type",
                    "minimum_years_experience",
                    "required_residence",
                    "work_jurisdiction",
                ),
            )
            receipt = LLMReceipt.bind(
                receipt_id="can-sponsor-visas-receipt",
                task="vacancy_eligibility_facts",
                model="fixture-model",
                prompt_version=VACANCY_ELIGIBILITY_PROMPT_VERSION,
                inputs=inputs,
                output=facts,
                created_at="2026-10-06T00:00:00Z",
            )
            return raw, facts, receipt, inputs

        quote = "We can sponsor visas!"
        raw, facts, receipt, inputs = bound_case(quote)
        self.assertTrue(supports_can_sponsor_visas(True, quote))
        self.assertEqual(
            facts,
            accept_vacancy_eligibility_facts(raw, facts, receipt, inputs=inputs),
        )

        for unsupported_quote in (
            "We cannot sponsor visas.",
            "We can sponsor visas for the right candidate.",
            "We can sponsor visas?",
            "We can sponsor visas!!",
        ):
            with self.subTest(quote=unsupported_quote):
                raw, facts, receipt, inputs = bound_case(unsupported_quote)
                self.assertFalse(
                    supports_can_sponsor_visas(True, unsupported_quote)
                )
                with self.assertRaisesRegex(
                    ContractValidationError, "exact quote grammar"
                ):
                    accept_vacancy_eligibility_facts(
                        raw, facts, receipt, inputs=inputs
                    )

        raw, facts, receipt, inputs = bound_case(quote, value=False)
        self.assertFalse(supports_can_sponsor_visas(False, quote))
        with self.assertRaisesRegex(ContractValidationError, "exact quote grammar"):
            accept_vacancy_eligibility_facts(raw, facts, receipt, inputs=inputs)

        class TextSubclass(str):
            pass

        self.assertFalse(supports_can_sponsor_visas(True, TextSubclass(quote)))

    def _bound_jurisdiction_case(
        self,
        *,
        code: str,
        quote: str,
        description: str = "",
        location_name: str = "London, United Kingdom",
        office_name: str = "London",
        office_location: str = "London, United Kingdom",
        offices: object = _default_offices,
        field: str = "work_jurisdiction",
    ) -> tuple[RawPosting, VacancyEligibilityFacts, LLMReceipt, dict[str, Any]]:
        raw, _ = LLMPipelineTests._structured_listing()
        raw = RawPosting(
            board=raw.board,
            job_id=raw.job_id,
            url=raw.url,
            fetched_at=raw.fetched_at,
            raw_json={
                "description": description,
                "location": {"name": location_name},
                "offices": (
                    [{"name": office_name, "location": office_location}]
                    if offices is self._default_offices
                    else offices
                ),
            },
        )
        raw = replace(raw, content_sha256=raw_posting_content_sha256(raw))
        inputs = vacancy_eligibility_input(raw)
        values = dict.fromkeys(self.fields)
        values[field] = code
        facts = VacancyEligibilityFacts(
            source_content_sha256=str(inputs["content_sha256"]),
            work_jurisdiction=values["work_jurisdiction"],
            required_residence=values["required_residence"],
            sponsorship_available=values["sponsorship_available"],
            minimum_years_experience=values["minimum_years_experience"],
            contract_type=values["contract_type"],
            source_evidence=(VacancyEligibilityEvidence(field=field, quote=quote),),
            unknown_fields=tuple(name for name in self.fields if name != field),
        )
        receipt = LLMReceipt.bind(
            receipt_id="structured-office-eligibility-receipt",
            task="vacancy_eligibility_facts",
            model="fixture-model",
            prompt_version="fixture-v1",
            inputs=inputs,
            output=facts,
            created_at="2026-10-06T00:00:00Z",
        )
        return raw, facts, receipt, inputs

    def test_explicit_uk_work_clause_supports_work_jurisdiction_only(self) -> None:
        quotes = (
            "We're open to distributed working within the UK.",
            "This role can be based in our London office, but we're open to distributed "
            "working within the UK (with ad hoc meetings in London).",
        )
        for quote in quotes:
            with self.subTest(quote=quote):
                raw, facts, receipt, inputs = self._bound_jurisdiction_case(
                    code="GB", quote=quote, description=quote
                )
                self.assertEqual(
                    facts,
                    accept_vacancy_eligibility_facts(
                        raw, facts, receipt, inputs=inputs
                    ),
                )

        quote = quotes[0]
        raw, facts, receipt, inputs = self._bound_jurisdiction_case(
            code="GB",
            quote=quote,
            description=quote,
            field="required_residence",
        )
        with self.assertRaisesRegex(
            ContractValidationError, "country code is absent"
        ):
            accept_vacancy_eligibility_facts(raw, facts, receipt, inputs=inputs)

    def test_uk_work_clause_helper_rejects_nonexact_and_malformed_inputs(self) -> None:
        valid = "We're open to distributed working within the UK."
        for code, quote in (
            ("GB", "We're not open to distributed working within the UK."),
            ("GB", "We're open to distributed working within the UK if approved."),
            ("GB", "We're open to distributed working within the UK and Ireland."),
            ("GB", "We're open to distributed working within England."),
            ("GB", "London"),
            ("gb", valid),
            (None, valid),
        ):
            with self.subTest(code=code, quote=quote):
                self.assertFalse(supports_explicit_uk_work_clause(code, quote))

        class TextSubclass(str):
            pass

        self.assertFalse(supports_explicit_uk_work_clause(TextSubclass("GB"), valid))
        self.assertFalse(
            supports_explicit_uk_work_clause("GB", TextSubclass(valid))
        )

    def test_work_jurisdiction_accepts_only_structured_gb_uk_office_binding(self) -> None:
        for code, quote in (
            ("GB", "London, United Kingdom"),
            ("GB", "United Kingdom"),
            ("UK", "London, United Kingdom"),
            ("UK", "United Kingdom"),
        ):
            with self.subTest(code=code, quote=quote):
                raw, facts, receipt, inputs = self._bound_jurisdiction_case(
                    code=code, quote=quote
                )
                self.assertEqual(
                    facts,
                    accept_vacancy_eligibility_facts(
                        raw, facts, receipt, inputs=inputs
                    ),
                )

    def test_work_jurisdiction_rejects_negated_and_multicountry_quotes(self) -> None:
        for quote in (
            "outside, United Kingdom",
            "not in, United Kingdom",
            "if located in, United Kingdom",
            "London or Dublin, United Kingdom",
            "France, United Kingdom",
            "Germany, United Kingdom",
            "Do not apply here, United Kingdom",
            "US, United Kingdom",
        ):
            with self.subTest(quote=quote):
                raw, facts, receipt, inputs = self._bound_jurisdiction_case(
                    code="GB", quote=quote, description=quote
                )
                with self.assertRaisesRegex(
                    ContractValidationError, "country code is absent"
                ):
                    accept_vacancy_eligibility_facts(
                        raw, facts, receipt, inputs=inputs
                    )

    def test_work_jurisdiction_requires_matching_office_location(self) -> None:
        raw, facts, receipt, inputs = self._bound_jurisdiction_case(
            code="GB",
            quote="London, United Kingdom",
            office_location="Paris, France",
        )
        with self.assertRaisesRegex(
            ContractValidationError, "country code is absent"
        ):
            accept_vacancy_eligibility_facts(raw, facts, receipt, inputs=inputs)

    def test_work_jurisdiction_rejects_missing_or_malformed_offices(self) -> None:
        for offices in (None, "London", {"name": "London"}, 42, []):
            with self.subTest(offices=offices):
                raw, facts, receipt, inputs = self._bound_jurisdiction_case(
                    code="GB",
                    quote="London, United Kingdom",
                    offices=offices,
                )
                with self.assertRaisesRegex(
                    ContractValidationError, "country code is absent"
                ):
                    accept_vacancy_eligibility_facts(
                        raw, facts, receipt, inputs=inputs
                    )

    def test_office_country_alias_does_not_establish_required_residence(self) -> None:
        raw, facts, receipt, inputs = self._bound_jurisdiction_case(
            code="GB", quote="London, United Kingdom", field="required_residence"
        )
        with self.assertRaisesRegex(
            ContractValidationError, "country code is absent"
        ):
            accept_vacancy_eligibility_facts(raw, facts, receipt, inputs=inputs)


class VerifiedEligibilityCaptureTests(unittest.TestCase):
    def _posting(self, **overrides: Any) -> RawPosting:
        fields = dict(
            board="example-board",
            job_id="job-0001",
            url="https://jobs.example.com/postings/job-0001",
            fetched_at="2026-10-06T08:17:57Z",
            raw_text="Frontend Engineer at Example Corp",
            raw_json={"title": "Frontend Engineer", "company": "Example Corp"},
            content_type="application/json",
            http_status=200,
        )
        fields.update(overrides)
        return RawPosting(**fields)

    def test_collector_and_public_capture_hashes_remain_distinct(self) -> None:
        original = self._posting()
        collector_digest = raw_posting_content_sha256(original)
        raw = replace(original, content_sha256=collector_digest)
        verified_digest, exact = verified_eligibility_capture(raw)
        inputs = vacancy_eligibility_input(raw)

        self.assertEqual(collector_digest, verified_digest)
        self.assertEqual(collector_digest, inputs["content_sha256"])
        self.assertEqual(collector_digest, raw.content_sha256)
        self.assertEqual(hashlib.sha256(exact).hexdigest(), inputs["public_capture_sha256"])
        self.assertNotEqual(inputs["content_sha256"], inputs["public_capture_sha256"])

        invalid_inputs = {**inputs, "public_capture_sha256": "0" * 64}
        facts = VacancyEligibilityFacts(
            source_content_sha256=collector_digest,
            work_jurisdiction=None,
            required_residence=None,
            sponsorship_available=None,
            minimum_years_experience=None,
            contract_type=None,
            source_evidence=(),
            unknown_fields=tuple(sorted(VACANCY_ELIGIBILITY_FIELDS)),
        )
        receipt = LLMReceipt.bind(
            receipt_id="wrong-public-capture",
            task="vacancy_eligibility_facts",
            model="fixture-model",
            prompt_version="fixture-v1",
            inputs=invalid_inputs,
            output=facts,
            created_at="2026-10-06T00:00:00Z",
        )
        with self.assertRaisesRegex(ContractValidationError, "input differs"):
            accept_vacancy_eligibility_facts(
                raw, facts, receipt, inputs=invalid_inputs
            )

    def test_mismatched_collector_digest_rejects(self) -> None:
        raw = replace(self._posting(), content_sha256="0" * 64)
        with self.assertRaisesRegex(ContractValidationError, "collector digest"):
            verified_eligibility_capture(raw)

    def test_mutated_capture_with_old_collector_digest_rejects(self) -> None:
        original = self._posting()
        stale_digest = raw_posting_content_sha256(original)
        tampered = replace(
            original,
            raw_text="Senior Backend Engineer at Example Corp",
            content_sha256=stale_digest,
        )
        with self.assertRaisesRegex(ContractValidationError, "collector digest"):
            verified_eligibility_capture(tampered)

    def test_base64_capture_keeps_its_existing_shared_hash_domain(self) -> None:
        blob = b"public listing payload for job-0001\n"
        raw = self._posting(
            raw_text=None,
            raw_json=None,
            content_type="application/pdf",
            public_content_base64=base64.b64encode(blob).decode("ascii"),
            content_sha256=hashlib.sha256(blob).hexdigest(),
        )
        digest, exact = verified_eligibility_capture(raw)
        self.assertEqual(blob, exact)
        self.assertEqual(hashlib.sha256(blob).hexdigest(), digest)
        self.assertEqual(digest, raw.content_sha256)

    def test_missing_digest_is_computed_without_mutating_the_posting(self) -> None:
        raw = self._posting()
        before = replace(raw)
        digest, exact = verified_eligibility_capture(raw)
        self.assertEqual(before, raw)
        self.assertIsNone(raw.content_sha256)
        self.assertEqual(raw_posting_content_sha256(raw), digest)
        self.assertEqual(exact, bind_public_listing(raw)[1])

    def test_unicode_json_uses_the_existing_collector_serialization(self) -> None:
        raw = self._posting(
            raw_text=None,
            raw_json={"title": "前端工程师", "note": "naïve café ☕"},
        )
        digest, exact = verified_eligibility_capture(raw)
        self.assertEqual(raw_posting_content_sha256(raw), digest)
        self.assertEqual(exact, bind_public_listing(raw)[1])
