from __future__ import annotations

import json
import copy
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from market_aligner.llm.codex_gateway import (
    CANDIDATE_POLICY_PROMPT_VERSION,
    CodexGatewayError,
    CodexSemanticGateway,
    make_candidate_policy_schema,
)


class CandidatePolicyRunner:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.schema: dict[str, Any] = {}
        self.prompt = ""

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        self.prompt = kwargs["input"]
        self.schema = json.loads(
            Path(command[command.index("--output-schema") + 1]).read_text(
                encoding="utf-8"
            )
        )
        Path(command[command.index("--output-last-message") + 1]).write_text(
            json.dumps(self.response), encoding="utf-8"
        )
        events = (
            {"type": "thread.started", "thread_id": "synthetic"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "1", "type": "agent_message"}},
            {"type": "turn.completed", "usage": {}},
        )
        return subprocess.CompletedProcess(
            command, 0, stdout="\n".join(json.dumps(event) for event in events), stderr=""
        )


def _response() -> dict[str, Any]:
    return {
        "authorised_jurisdictions": {
            "value": [{"value": "GB", "source_ids": ["profile-rights"]}],
            "source_ids": ["profile-rights"],
        },
        "current_residence": None,
        "requires_sponsorship": {
            "value": False,
            "source_ids": ["job-scope-policy"],
        },
        "maximum_years_required": None,
        "excluded_contract_types": None,
    }


def _gateway(root: Path, response: dict[str, Any]):
    binary = root / "codex"
    binary.write_bytes(b"synthetic codex executable")
    runner = CandidatePolicyRunner(response)
    gateway = CodexSemanticGateway(
        model="synthetic-model",
        codex_binary=str(binary),
        environment={"HOME": str(root), "PATH": "/usr/bin"},
        runner=runner,
    )
    return gateway, runner


def test_candidate_policy_schema_requires_cited_null_or_typed_value() -> None:
    schema = make_candidate_policy_schema(["GB", "US"], ["contract", "permanent"])
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "authorised_jurisdictions",
        "current_residence",
        "requires_sponsorship",
        "maximum_years_required",
        "excluded_contract_types",
    }
    assert schema["properties"]["current_residence"]["anyOf"][1]["properties"]["value"]["enum"] == ["GB", "US"]
    assert schema["properties"]["excluded_contract_types"]["anyOf"][1]["properties"]["value"]["items"]["properties"]["value"]["enum"] == ["contract", "permanent"]
    source_ids_schema = schema["properties"]["requires_sponsorship"]["anyOf"][1]["properties"]["source_ids"]
    assert "uniqueItems" not in source_ids_schema

    class StringSubclass(str):
        pass

    with pytest.raises(ValueError, match="entries must be non-empty strings"):
        make_candidate_policy_schema([StringSubclass("GB")], ["contract"])
    with pytest.raises(ValueError, match="entries must be unique"):
        make_candidate_policy_schema(["GB", "GB"], ["contract"])


def test_gateway_binds_candidate_policy_to_supplied_catalog_and_schema() -> None:
    records = [
        {
            "evidence_id": "profile-rights",
            "kind": "current_profile_field",
            "status": "explicit",
            "claim": '"GB"',
        },
        {
            "evidence_id": "job-scope-policy",
            "kind": "preferences",
            "status": "verified",
            "claim": "Synthetic source-bound policy for job jurisdiction.",
        },
        {
            "evidence_id": "old-policy",
            "kind": "preferences",
            "status": "explicit",
            "claim": "Synthetic earlier policy statement invalidated by correction.",
        },
    ]
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), _response())
        selection, receipt = gateway.extract_candidate_policy(
            records,
            target_job_jurisdiction="GB",
            correction_assessments=[
                {
                    "source_evidence_id": "old-policy",
                    "relationship": "not_applicable",
                    "affected_evidence_ids": [],
                }
            ],
            iso_codes=["GB", "US"],
            contract_types=["contract", "permanent"],
        )

    assert selection == _response()
    assert len(runner.calls) == 1
    assert runner.calls[0][1]["timeout"] > 0
    assert runner.schema["additionalProperties"] is False
    assert CANDIDATE_POLICY_PROMPT_VERSION in runner.prompt
    assert "supplied factual catalog" in runner.prompt
    assert "you never see real profile" not in runner.prompt.lower()
    assert "Synthetic source-bound policy for job jurisdiction." in runner.prompt
    assert "source_ref" not in runner.prompt
    assert receipt.task == "candidate_policy_extraction"
    assert receipt.transport is not None
    assert receipt.transport.invocation_count == 1


def test_current_candidate_policy_document_roundtrips_through_native_admission() -> None:
    from market_aligner.llm.contracts import (
        LLMReceipt,
        LLMTransportReceipt,
        canonical_hash,
    )
    from market_aligner.processing import (
        admit_current_candidate_facts,
        admit_saved_candidate_policy,
        bind_current_candidate_policy_refs,
        build_current_candidate_policy_canary_document,
    )

    records = [
        {
            "evidence_id": "profile-rights",
            "kind": "current_profile_field",
            "status": "explicit",
            "claim": '"GB"',
        },
        {
            "evidence_id": "job-scope-policy",
            "kind": "preferences",
            "status": "verified",
            "claim": "Synthetic source-bound policy for job jurisdiction.",
        },
        {
            "evidence_id": "old-policy",
            "kind": "preferences",
            "status": "explicit",
            "claim": "Synthetic earlier policy statement.",
        },
    ]
    corrections = [
        {
            "source_evidence_id": "old-policy",
            "relationship": "not_applicable",
            "affected_evidence_ids": [],
        }
    ]
    iso_codes = ["GB", "US"]
    contract_types = ["contract", "permanent"]
    with tempfile.TemporaryDirectory() as temporary:
        gateway, _runner = _gateway(Path(temporary), _response())
        selection, receipt = gateway.extract_candidate_policy(
            records,
            target_job_jurisdiction="GB",
            correction_assessments=corrections,
            iso_codes=iso_codes,
            contract_types=contract_types,
        )

    request = {
        "schema": "market-aligner.candidate-policy-input.v1",
        "target_job_jurisdiction": "GB",
        "factual_catalog": records,
        "correction_assessments": corrections,
        "invalidated_ids": [],
        "allowed_iso_codes": iso_codes,
        "allowed_contract_types": contract_types,
    }
    snapshot_hashes = {
        "profile_sha256": "a" * 64,
        "evidence_ledger_sha256": "b" * 64,
    }
    provenance = {
        "activation_file_sha256": "c" * 64,
        "activation_name": "activation-" + "1" * 32 + ".json",
        "activation_sha256": "d" * 64,
        "active_snapshot_hashes": snapshot_hashes,
        "profile_id": "prf_" + "e" * 32,
        "recovery_manifest_sha256": "f" * 64,
    }
    target = {
        "target_job_jurisdiction": "GB",
        "target_job_key": "greenhouse:synthetic:42",
    }
    document = build_current_candidate_policy_canary_document(
        **provenance,
        receipt=receipt,
        request=request,
        selection=selection,
        **target,
    )
    assert document["request_matches_receipt"] is True

    catalog = {
        row["evidence_id"]: {
            **row,
            "source_ref": f"synthetic://{row['evidence_id']}",
            "content_sha256": "9" * 64,
        }
        for row in records
    }

    def verify_receipt(value, *, inputs, output):
        if type(value) is not dict:
            raise ValueError("invalid synthetic receipt")
        receipt_value = dict(value)
        transport_value = receipt_value.pop("transport")
        verified = LLMReceipt(
            **{
                **receipt_value,
                "transport": LLMTransportReceipt(**transport_value),
            }
        )
        if (
            verified.input_sha256 != canonical_hash(inputs)
            or verified.output_sha256 != canonical_hash(output)
        ):
            raise ValueError("synthetic receipt binding differs")
        return None

    admission = admit_saved_candidate_policy(
        document,
        expected_provenance=provenance,
        expected_target=target,
        expected_request=request,
        catalog=catalog,
        verify_receipt=verify_receipt,
        bind_refs=bind_current_candidate_policy_refs,
        admit_refs=admit_current_candidate_facts,
    )
    assert admission.status_downgraded is False
    assert admission.effective["requires_sponsorship"] is False

    changed_request = copy.deepcopy(request)
    changed_request["target_job_jurisdiction"] = "US"
    with pytest.raises(ValueError, match="^invalid saved candidate policy$"):
        build_current_candidate_policy_canary_document(
            **provenance,
            receipt=receipt,
            request=changed_request,
            selection=selection,
            **target,
        )
    changed_selection = copy.deepcopy(selection)
    changed_selection["current_residence"] = {
        "value": "GB",
        "source_ids": ["profile-rights"],
    }
    with pytest.raises(ValueError, match="^invalid saved candidate policy$"):
        build_current_candidate_policy_canary_document(
            **provenance,
            receipt=receipt,
            request=request,
            selection=changed_selection,
            **target,
        )
    bad_provenance = {**provenance, "activation_sha256": "D" * 64}
    with pytest.raises(ValueError, match="^invalid saved candidate policy$"):
        build_current_candidate_policy_canary_document(
            **bad_provenance,
            receipt=receipt,
            request=request,
            selection=selection,
            **target,
        )

    request["factual_catalog"][0]["claim"] = "mutated after build"
    selection["requires_sponsorship"]["value"] = True
    assert document["request"]["factual_catalog"][0]["claim"] == '"GB"'
    assert document["selection"]["requires_sponsorship"]["value"] is False


@pytest.mark.parametrize(
    "records,corrections,jurisdiction",
    [
        ([{"evidence_id": "x", "kind": "k", "status": "explicit", "claim": "c"},
          {"evidence_id": "x", "kind": "k", "status": "explicit", "claim": "c"}], [], "GB"),
        ([{"evidence_id": "x", "kind": "k", "status": "explicit", "claim": "c"}],
         [{"source_evidence_id": "missing", "relationship": "corrects",
           "affected_evidence_ids": ["x"]}], "GB"),
        ([{"evidence_id": "x", "kind": "k", "status": "explicit", "claim": "c"}], [], "ZZ"),
        ([{"evidence_id": "x", "kind": "k", "status": "unsupported", "claim": "c"}], [], "GB"),
    ],
)
def test_gateway_refuses_malformed_catalog_or_scope_before_dispatch(
    records, corrections, jurisdiction
) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), _response())
        with pytest.raises(CodexGatewayError):
            gateway.extract_candidate_policy(
                records,
                target_job_jurisdiction=jurisdiction,
                correction_assessments=corrections,
                iso_codes=["GB", "US"],
                contract_types=["contract", "permanent"],
            )
    assert runner.calls == []
