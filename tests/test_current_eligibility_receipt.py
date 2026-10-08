import json
import copy

import pytest

from market_aligner.applications.production_handoff import (
    _current_eligibility_receipt,
)
from market_aligner.assessment.eligibility import (
    EligibilityInput,
    EligibilityPolicy,
    assess_eligibility,
)
from market_aligner.processing import (
    _validate_current_eligibility_document,
    admit_current_candidate_facts,
    admit_saved_candidate_policy,
    bind_current_candidate_policy_refs,
    build_current_eligibility_receipt_from_decision,
    parse_current_eligibility_receipt,
    validate_current_eligibility_binding,
)
from market_aligner.llm.contracts import (
    VacancyEligibilityEvidence,
    VacancyEligibilityFacts,
)


def _binding():
    return {
        "profile_id": "prf_synthetic",
        "profile_version": "profile.v1",
        "track": "synthetic-track",
        "source_job_key": "board:synthetic:1",
        **{
            key: f"{number:064x}"
            for number, key in enumerate(
                (
                    "profile_file_sha256",
                    "evidence_file_sha256",
                    "normalized_json_sha256",
                    "source_content_sha256",
                    "processing_receipt_sha256",
                    "promotion_receipt_sha256",
                    "candidate_policy_receipt_sha256",
                    "vacancy_facts_receipt_sha256",
                    "activation_receipt_sha256",
                    "candidate_facts_sha256",
                    "vacancy_facts_sha256",
                ),
                start=1,
            )
        },
    }


def _decision(*, authorised_jurisdictions, requires_sponsorship=None):
    policy = EligibilityPolicy(
        authorised_jurisdictions=authorised_jurisdictions,
        current_residence="GB",
        requires_sponsorship=requires_sponsorship,
        maximum_years_required=4,
        excluded_contract_types=frozenset(),
    )
    facts = EligibilityInput(
        work_jurisdiction="GB",
        required_residence="GB",
        sponsorship_available=None,
        minimum_years_experience=2,
        contract_type="permanent",
    )
    return assess_eligibility(facts, policy)


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        (_decision(authorised_jurisdictions=frozenset({"GB"})), "pass"),
        (_decision(authorised_jurisdictions=None), "review"),
        (
            _decision(
                authorised_jurisdictions=frozenset(),
                requires_sponsorship=False,
            ),
            "reject",
        ),
    ],
)
def test_current_receipt_roundtrips_existing_assessor_decisions(decision, expected):
    raw = build_current_eligibility_receipt_from_decision(
        binding=_binding(), decision=decision
    )

    parsed = parse_current_eligibility_receipt(raw, expected_binding=_binding())

    assert parsed["decision"] == expected
    assert parsed["reasons"] == list(decision.reasons)
    assert parsed["unknowns"] == list(decision.unknowns)
    assert parsed["eligibility_authority"] is (expected == "pass")
    assert parsed["release_authority"] is False
    assert parsed["submission_authority"] is False
    assert raw == json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_current_receipt_refuses_binding_drift_and_non_string_keys():
    decision = _decision(authorised_jurisdictions=frozenset({"GB"}))
    raw = build_current_eligibility_receipt_from_decision(
        binding=_binding(), decision=decision
    )
    changed = _binding()
    changed["vacancy_facts_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="^invalid current eligibility receipt$"):
        parse_current_eligibility_receipt(raw, expected_binding=changed)

    bad_binding = _binding()
    bad_binding[7] = "x"
    with pytest.raises(ValueError, match="^invalid current eligibility receipt$"):
        validate_current_eligibility_binding(bad_binding)

    bad_document = json.loads(raw)
    bad_document[7] = "x"
    with pytest.raises(ValueError, match="^invalid current eligibility receipt$"):
        _validate_current_eligibility_document(bad_document)


def test_current_receipt_rejects_duplicate_keys_noncanonical_bytes_and_authority():
    decision = _decision(authorised_jurisdictions=frozenset({"GB"}))
    raw = build_current_eligibility_receipt_from_decision(
        binding=_binding(), decision=decision
    )
    duplicate = raw.replace(b'"decision":"pass"', b'"decision":"pass","decision":"pass"')

    forged_release_authority = raw.replace(
        b'"release_authority":false', b'"release_authority":true'
    )
    for candidate in (duplicate, raw + b"\n", forged_release_authority):
        with pytest.raises(ValueError, match="^invalid current eligibility receipt$"):
            parse_current_eligibility_receipt(candidate, expected_binding=_binding())


def test_current_receipt_decision_must_match_sorted_reason_and_unknown_tokens():
    decision = _decision(authorised_jurisdictions=frozenset())
    raw = build_current_eligibility_receipt_from_decision(
        binding=_binding(), decision=decision
    )
    document = json.loads(raw)
    document["reasons"] = ["work_authorisation_mismatch", "sponsorship_unavailable"]

    with pytest.raises(ValueError, match="^invalid current eligibility receipt$"):
        _validate_current_eligibility_document(document)


def _vacancy_facts():
    values = {
        "work_jurisdiction": "GB",
        "required_residence": "GB",
        "sponsorship_available": True,
        "minimum_years_experience": 2,
        "contract_type": "permanent",
    }
    evidence = tuple(
        VacancyEligibilityEvidence(field=field, quote=f"Synthetic source for {field}")
        for field in sorted(values)
    )
    return VacancyEligibilityFacts(
        source_content_sha256="a" * 64,
        **values,
        source_evidence=evidence,
        unknown_fields=(),
    )


def _candidate_policy(**changes):
    candidate = {
        "authorised_jurisdictions": ["GB"],
        "current_residence": "GB",
        "requires_sponsorship": False,
        "maximum_years_required": 3,
        "excluded_contract_types": [],
    }
    candidate.update(changes)
    return candidate


def test_current_eligibility_join_uses_existing_assessor_and_keeps_unknowns():
    binding = _binding()
    passed = parse_current_eligibility_receipt(
        _current_eligibility_receipt(
            binding=binding,
            candidate_facts=_candidate_policy(),
            vacancy_facts=_vacancy_facts(),
        ),
        expected_binding=binding,
    )
    assert passed["decision"] == "pass"
    assert passed["eligibility_authority"] is True
    assert passed["release_authority"] is False
    assert passed["submission_authority"] is False

    reviewed = parse_current_eligibility_receipt(
        _current_eligibility_receipt(
            binding=binding,
            candidate_facts=_candidate_policy(
                authorised_jurisdictions=None,
                requires_sponsorship=None,
                excluded_contract_types=None,
            ),
            vacancy_facts=_vacancy_facts(),
        ),
        expected_binding=binding,
    )
    assert reviewed["decision"] == "review"
    assert reviewed["eligibility_authority"] is False
    assert reviewed["unknowns"]


@pytest.mark.parametrize(
    "changes",
    [
        {"requires_sponsorship": 1},
        {"maximum_years_required": True},
        {"maximum_years_required": 10**10000},
        {"authorised_jurisdictions": ["GB", "GB"]},
        {"excluded_contract_types": ["invented"]},
        {"current_residence": "uk"},
    ],
)
def test_current_eligibility_join_refuses_malformed_policy_values(changes):
    with pytest.raises(ValueError, match="^current eligibility inputs are malformed$"):
        _current_eligibility_receipt(
            binding=_binding(),
            candidate_facts=_candidate_policy(**changes),
            vacancy_facts=_vacancy_facts(),
        )


def test_saved_policy_validation_composes_receipt_binding_and_native_admission():
    evidence_id = "profile-field:constraints.work_authorisation_uk"
    catalog = {
        evidence_id: {
            "evidence_id": evidence_id,
            "kind": "current_profile_field",
            "status": "explicit",
            "claim": '"United Kingdom"',
            "source_ref": "profile.yaml#/constraints/work_authorisation_uk",
            "content_sha256": "a" * 64,
        }
    }
    selection = {
        "authorised_jurisdictions": None,
        "current_residence": {
            "value": "GB",
            "source_ids": [evidence_id],
        },
        "requires_sponsorship": None,
        "maximum_years_required": None,
        "excluded_contract_types": None,
    }
    request = {
        "schema": "market-aligner.candidate-policy-input.v1",
        "invalidated_ids": ["old-evidence"],
    }
    provenance = {
        "activation_file_sha256": "b" * 64,
        "activation_name": "activation-" + "1" * 32 + ".json",
        "activation_sha256": "c" * 64,
        "active_snapshot_hashes": {"profile_sha256": "d" * 64},
        "profile_id": "prf_synthetic",
        "recovery_manifest_sha256": "e" * 64,
    }
    target = {
        "target_job_jurisdiction": "GB",
        "target_job_key": "board:synthetic:1",
    }
    document = {
        "schema": "market-aligner.current-candidate-policy-canary.v1",
        **provenance,
        **target,
        "receipt": {"synthetic_receipt": True},
        "request": copy.deepcopy(request),
        "request_matches_receipt": True,
        "selection": copy.deepcopy(selection),
    }
    calls = []

    def verify_receipt(receipt, *, inputs, output):
        calls.append("verify")
        assert receipt == {"synthetic_receipt": True}
        assert inputs == request
        assert type(output) is dict
        return None

    def bind_refs(output, *, catalog):
        calls.append("bind")
        return bind_current_candidate_policy_refs(output, catalog=catalog)

    def admit_refs(bound, *, catalog, invalidated_ids):
        calls.append("admit")
        assert type(invalidated_ids) is frozenset
        return admit_current_candidate_facts(
            bound, catalog=catalog, invalidated_ids=invalidated_ids
        )

    before = copy.deepcopy((document, provenance, target, request, catalog))
    admission = admit_saved_candidate_policy(
        document,
        expected_provenance=provenance,
        expected_target=target,
        expected_request=request,
        catalog=catalog,
        verify_receipt=verify_receipt,
        bind_refs=bind_refs,
        admit_refs=admit_refs,
    )

    assert calls == ["verify", "bind", "admit"]
    assert admission.effective["current_residence"] == "GB"
    assert admission.status_downgraded is False
    assert (document, provenance, target, request, catalog) == before

    malformed_schema = dict(document, schema=True)
    calls.clear()
    with pytest.raises(ValueError, match="^invalid saved candidate policy$"):
        admit_saved_candidate_policy(
            malformed_schema,
            expected_provenance=provenance,
            expected_target=target,
            expected_request=request,
            catalog=catalog,
            verify_receipt=verify_receipt,
            bind_refs=bind_refs,
            admit_refs=admit_refs,
        )
    assert calls == []

    invalidated_selection = copy.deepcopy(document)
    invalidated_selection["selection"]["current_residence"]["source_ids"] = [
        "old-evidence"
    ]
    old_entry = dict(catalog[evidence_id], evidence_id="old-evidence")
    invalidated_catalog = {"old-evidence": old_entry}
    with pytest.raises(ValueError, match="invalid candidate reference"):
        admit_saved_candidate_policy(
            invalidated_selection,
            expected_provenance=provenance,
            expected_target=target,
            expected_request=request,
            catalog=invalidated_catalog,
            verify_receipt=verify_receipt,
            bind_refs=bind_refs,
            admit_refs=admit_refs,
        )
