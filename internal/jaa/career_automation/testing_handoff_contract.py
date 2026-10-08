from __future__ import annotations

import hashlib

import json

from dataclasses import dataclass

from typing import Mapping

from .handoff_admission import ReferenceRequest, ResolvedReference, SelectionPolicyRules

from .market_aligner_handoff import CANDIDATE_INTENT_SCHEMA, HANDOFF_SCHEMA, canonical_json_bytes, canonical_sha256

PROFILE_ID = "prf_0123456789abcdef0123456789abcdef"

PROFILE_VERSION = "synthetic-profile-v1"

COMMIT_SHA = "1" * 40

TRUST_ROOT_ID = "synthetic-programme-root-v1"

ISSUED_AT = "2026-08-10T08:00:00Z"

VALID_UNTIL = "2026-08-10T12:00:00Z"

def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

@dataclass(frozen=True)
class SyntheticHandoffFixture:
    raw: bytes
    context_bytes: bytes
    resolver: "SyntheticResolver"
    payload: Mapping[str, object]

class SyntheticContextAuthenticator:
    authenticator_identity_sha256 = _digest(b"synthetic-context-authenticator-v1")

    @staticmethod
    def proof(unsigned: Mapping[str, object]) -> str:
        return canonical_sha256(
            {
                "context": dict(unsigned),
                "schema_version": "jaa.synthetic-admission-context-proof.v1",
            }
        )

    def authenticate(
        self,
        *,
        context_bytes: bytes,
        handoff_bytes: bytes,
        evaluated_at: str,
    ) -> None:
        document = json.loads(context_bytes)
        proof = document.pop("trust_proof_sha256", None)
        if proof != self.proof(document):
            raise ValueError("context proof is not trusted")
        if (
            document.get("environment") != "synthetic"
            or document.get("trust_root_id") != TRUST_ROOT_ID
            or document.get("trust_mode") != "protected_local_outbox"
        ):
            raise ValueError("synthetic context scope is not trusted")
        if document["handoff_root_sha256"] != _digest(handoff_bytes):
            raise ValueError("context root differs")
        if evaluated_at < document["issued_at"]:
            raise ValueError("context is future-dated")

class SyntheticResolver:
    resolver_identity_sha256 = _digest(b"synthetic-typed-resolver-v1")
    synthetic_trust_root_id = TRUST_ROOT_ID

    def __init__(
        self,
        objects: Mapping[str, bytes],
        *,
        valid_until: str = VALID_UNTIL,
        trust_root_id: str = TRUST_ROOT_ID,
        rules: SelectionPolicyRules | None = None,
    ) -> None:
        self.objects = dict(objects)
        self.valid_until = valid_until
        self.trust_root_id = trust_root_id
        self.rules = rules or SelectionPolicyRules(300, 21_600, 86_400, False)
        self.resolve_calls: list[str] = []
        self.authenticate_calls: list[str] = []
        self.metadata_mutation: Mapping[str, object] = {}
        self.valid_until_by_reference: dict[str, str | None] = {}

    @staticmethod
    def _proof(unsigned_metadata: Mapping[str, object]) -> str:
        return canonical_sha256(
            {
                "metadata": dict(unsigned_metadata),
                "schema_version": "jaa.synthetic-reference-proof.v1",
            }
        )

    def resolve(self, request: ReferenceRequest) -> ResolvedReference:
        self.resolve_calls.append(request.spec.reference_key)
        exact = self.objects[request.sha256]
        valid_until = (
            None
            if request.spec.freshness_class == "immutable"
            else self.valid_until_by_reference.get(
                request.spec.reference_key, self.valid_until
            )
        )
        unsigned_metadata = {
            "issued_at": ISSUED_AT,
            "issuer_id": "synthetic-market-aligner-issuer-v1",
            "object_sha256": request.sha256,
            "reference_key": request.spec.reference_key,
            "schema_version": request.spec.schema_version,
            "subject": dict(request.expected_subject),
            "trust_root_id": self.trust_root_id,
            "type_id": request.spec.type_id,
            "valid_until": valid_until,
        }
        metadata = {
            **unsigned_metadata,
            "trust_proof_sha256": self._proof(unsigned_metadata),
        }
        metadata.update(self.metadata_mutation)
        return ResolvedReference(exact, canonical_json_bytes(metadata))

    def authenticate(
        self,
        *,
        metadata_bytes: bytes,
        exact_bytes: bytes,
        admission_context_bytes: bytes | None,
        evaluated_at: str,
    ) -> None:
        metadata = json.loads(metadata_bytes)
        self.authenticate_calls.append(metadata["reference_key"])
        supplied = metadata.pop("trust_proof_sha256", None)
        if metadata.get("object_sha256") != _digest(exact_bytes):
            raise ValueError("reference object differs")
        if supplied != self._proof(metadata):
            raise ValueError("reference proof is not trusted")
        if admission_context_bytes is None:
            raise ValueError("authenticated resolver requires context")
        context = json.loads(admission_context_bytes)
        if context["trust_root_id"] != metadata["trust_root_id"]:
            raise ValueError("reference trust root differs")

def build_handoff_fixture(
    *,
    compatibility: bool = False,
    decision_salt: str = "initial",
    valid_until: str = VALID_UNTIL,
    employer_dossier_required: bool = False,
) -> SyntheticHandoffFixture:
    rules = SelectionPolicyRules(300, 21_600, 86_400, employer_dossier_required)
    objects: dict[str, bytes] = {}

    def retain(value: bytes) -> str:
        digest = _digest(value)
        objects[digest] = value
        return digest

    authority_source_sha256 = retain(
        canonical_json_bytes(
            {"schema_version": "market-aligner.candidate-authority-source.v1", "synthetic": True}
        )
    )
    intent_sha256 = retain(
        canonical_json_bytes(
            {
                "authority_revision": 1,
                "authority_source_sha256": authority_source_sha256,
                "created_at": "2026-08-10T08:30:00Z",
                "geography_priority": [
                    {"rank": 1, "region_code": "UK", "work_mode": "remote"},
                    {"rank": 2, "region_code": "UK", "work_mode": "hybrid"},
                    {"rank": 3, "region_code": "UK", "work_mode": "onsite"},
                    {"rank": 4, "region_code": "RO", "work_mode": "remote"},
                    {"rank": 5, "region_code": "EU", "work_mode": "remote"},
                ],
                "profile_id": PROFILE_ID,
                "profile_version": PROFILE_VERSION,
                "role_track_ids": ["applied_ai"],
                "schema_version": CANDIDATE_INTENT_SCHEMA,
            }
        )
    )
    evidence_ledger_sha256 = retain(canonical_json_bytes({"synthetic": "evidence-ledger"}))
    eligibility_evidence_sha256 = retain(canonical_json_bytes({"synthetic": "work-right"}))
    eligibility_receipt_sha256 = retain(
        canonical_json_bytes({"decision": decision_salt, "kind": "eligibility"})
    )
    assessment_receipt_sha256 = retain(
        canonical_json_bytes({"decision": decision_salt, "kind": "assessment"})
    )
    selection_receipt_sha256 = retain(
        canonical_json_bytes({"decision": decision_salt, "kind": "selection"})
    )
    scoring_parameters_sha256 = retain(canonical_json_bytes({"version": "synthetic-v1"}))
    location_facts_sha256 = retain(canonical_json_bytes({"country_code": "GB", "remote": True}))
    raw_listing_sha256 = retain(b"Synthetic exact public vacancy listing")
    requirements_sha256 = retain(
        canonical_json_bytes({"requirements": ["python", "reliability"]})
    )
    vacancy_snapshot_sha256 = retain(
        canonical_json_bytes({"snapshot": "synthetic-v1"})
    )
    selection_policy_sha256 = retain(
        canonical_json_bytes(
            {
                **rules.document(),
                "schema_version": "market-aligner.selection-policy.v1",
            }
        )
    )
    dossier_sha256 = (
        retain(canonical_json_bytes({"employer": "Synthetic Systems Ltd"}))
        if employer_dossier_required
        else None
    )
    provenance = {
        "adapter": "greenhouse",
        "canonical_url": "https://job-boards.greenhouse.io/synthetic/jobs/12345",
        "discovered_at": "2026-08-10T09:00:00.125Z" if compatibility else "2026-08-10T09:00:00Z",
        "fetched_at": "2026-08-10T09:30:00.250Z" if compatibility else "2026-08-10T09:30:00Z",
        "source_job_id": "12345",
    }
    job_key = "job_" + canonical_sha256(
        {
            "adapter": provenance["adapter"],
            "canonical_url": provenance["canonical_url"],
            "source_job_id": provenance["source_job_id"],
        }
    )
    score = 1 if compatibility else 1.0
    zero = -0.0 if compatibility else 0.0
    payload = {
        "assessment": {
            "assessment_receipt_sha256": assessment_receipt_sha256,
            "extraction_confidence": score,
            "final": score,
            "fit": score,
            "fit_components": {"skills": score},
            "fit_status": "uncalibrated",
            "opportunity": score,
            "opportunity_components": {"market": zero},
            "scoring_parameters_sha256": scoring_parameters_sha256,
        },
        "candidate_intent_sha256": intent_sha256,
        "created_at": "2026-08-10T10:00:00.500Z" if compatibility else "2026-08-10T10:00:00Z",
        "eligibility": {
            "checks": [
                {"code": "work_right", "evidence_sha256": eligibility_evidence_sha256, "outcome": "pass"}
            ],
            "decision": "eligible",
            "eligibility_receipt_sha256": eligibility_receipt_sha256,
            "hard_gate_passed": True,
        },
        "employer_dossier_sha256": dossier_sha256,
        "evidence_ledger_sha256": evidence_ledger_sha256,
        "job_key": job_key,
        "producer": {"commit_sha": COMMIT_SHA, "product": "market-aligner"},
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "selection": {
            "decision": "selected_for_application",
            "geography_bucket": "UK_REMOTE",
            "geography_priority_rank": 1,
            "hard_gate_passed": True,
            "rationale_codes": ["synthetic_fit"],
            "selection_policy_sha256": selection_policy_sha256,
            "selection_receipt_sha256": selection_receipt_sha256,
        },
        "vacancy": {
            "company_name": "Cafe\u0301 Systems" if compatibility else "Café Systems",
            "location": {
                "country_code": "GB",
                "facts_sha256": location_facts_sha256,
                "locality": "London",
                "raw_text": "Remote, United Kingdom",
                "region": "England",
                "work_mode": "remote",
            },
            "provenance": provenance,
            "raw_listing_sha256": raw_listing_sha256,
            "requirements_sha256": requirements_sha256,
            "role_title": "Reliability Engineer",
            "vacancy_snapshot_sha256": vacancy_snapshot_sha256,
        },
    }
    envelope = {
        "payload": payload,
        "payload_sha256": canonical_sha256(payload),
        "schema_version": HANDOFF_SCHEMA,
    }
    raw = canonical_json_bytes(envelope)
    unsigned_context = {
        "environment": "synthetic",
        "handoff_root_sha256": _digest(raw),
        "issued_at": "2026-08-10T10:01:00Z",
        "producer_commit_sha": COMMIT_SHA,
        "producer_product": "market-aligner",
        "source_record_sha256": _digest(b"synthetic-atomic-outbox-record" + raw),
        "trust_mode": "protected_local_outbox",
        "trust_root_id": TRUST_ROOT_ID,
    }
    context = canonical_json_bytes(
        {
            **unsigned_context,
            "trust_proof_sha256": SyntheticContextAuthenticator.proof(unsigned_context),
        }
    )
    return SyntheticHandoffFixture(
        raw=raw,
        context_bytes=context,
        resolver=SyntheticResolver(objects, valid_until=valid_until, rules=rules),
        payload=payload,
    )
