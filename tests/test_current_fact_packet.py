from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from market_aligner.profiler.fact_packet import (
    compile_selected_facts,
    serialize_projection_documents,
    validate_current_profile_binding,
    validate_current_profile_projection_receipt,
)


def _inputs():
    records = [
        {
            "evidence_id": "ev-project",
            "claim": " Built and tested a café-ordering service. ☕ ",
            "status": "verified",
            "ignored_private_source_ref": object(),
        },
        {"evidence_id": "ev-inference", "claim": "Not exported", "status": "inference"},
        {"evidence_id": "ev-current", "claim": "Not exported", "status": "unverified_current"},
    ]
    selection = [
        {
            "evidence_id": "ev-project",
            "proof_class": "portfolio_artifact",
            "document_targets": ["cover_letter", "cv"],
        }
    ]
    excluded = ["ev-inference", "ev-current"]
    hashes = {"recovery_manifest": "a" * 64, "profile": "b" * 64, "evidence": "c" * 64}
    return records, selection, excluded, hashes


def test_compile_selected_facts_preserves_exact_claim_and_selection_binding():
    records, selection, excluded, hashes = _inputs()
    original = json.loads(json.dumps({"selection": selection, "excluded": excluded}))

    packet_bytes, bindings = compile_selected_facts(records, selection, excluded, hashes)
    packet = json.loads(packet_bytes)

    assert packet_bytes.endswith(b"\n")
    assert packet["schema_version"] == "market-aligner.current-factual-statements.v1"
    assert packet["source_hashes"] == hashes
    assert packet["statements"] == [
        {
            "id": "ev-project",
            "kind": "portfolio_artifact",
            "proof_class": "portfolio_artifact",
            "statement": records[0]["claim"],
            "document_targets": ["cover_letter", "cv"],
        }
    ]
    assert bindings == [
        {
            "id": "ev-project",
            "kind": "portfolio_artifact",
            "proof_class": "portfolio_artifact",
            "statement_sha256": hashlib.sha256(records[0]["claim"].encode()).hexdigest(),
        }
    ]
    assert json.loads(json.dumps({"selection": selection, "excluded": excluded})) == original
    assert b"Not exported" not in packet_bytes


def test_compile_selected_facts_is_deterministic_and_preserves_selection_order():
    records, selection, excluded, hashes = _inputs()
    records.append({"evidence_id": "ev-second", "claim": "A second exact fact.", "status": "explicit"})
    selection.append(
        {
            "evidence_id": "ev-second",
            "proof_class": "verified_claim",
            "document_targets": ["cv"],
        }
    )
    excluded.remove("ev-current")
    first = compile_selected_facts(records, selection, excluded, hashes)
    second = compile_selected_facts(records, selection, excluded, hashes)
    assert first == second
    assert [row["id"] for row in json.loads(first[0])["statements"]] == [
        "ev-project",
        "ev-second",
    ]
    assert [row["id"] for row in first[1]] == ["ev-project", "ev-second"]


@pytest.mark.parametrize(
    ("mutate",),
    [
        (lambda r, s, e, h: r.append(dict(r[0])),),
        (lambda r, s, e, h: r[0].update(evidence_id=" "),),
        (lambda r, s, e, h: r[0].update(claim="  "),),
        (lambda r, s, e, h: s.append(dict(s[0])),),
        (lambda r, s, e, h: s[0].update(evidence_id="missing"),),
        (lambda r, s, e, h: s[0].update(proof_class="unknown"),),
        (lambda r, s, e, h: s[0].update(document_targets=[]),),
        (lambda r, s, e, h: s[0].update(document_targets=["cv", "cv"]),),
        (lambda r, s, e, h: s[0].update(document_targets=["other"]),),
        (lambda r, s, e, h: e.append("ev-inference"),),
        (lambda r, s, e, h: h.update(profile="A" * 64),),
        (lambda r, s, e, h: h.update(extra="d" * 64),),
    ],
)
def test_compile_selected_facts_rejects_malformed_or_conflicting_inputs(mutate):
    records, selection, excluded, hashes = _inputs()
    mutate(records, selection, excluded, hashes)
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, selection, excluded, hashes)


@pytest.mark.parametrize(
    "status",
    ["inference", "unverified_current"],
)
def test_compile_selected_facts_never_exports_inference_or_unverified_rows(status):
    records, selection, excluded, hashes = _inputs()
    selection[0]["evidence_id"] = (
        "ev-current" if status == "unverified_current" else "ev-inference"
    )
    excluded.remove(selection[0]["evidence_id"])
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, selection, excluded, hashes)


def test_compile_selected_facts_rejects_empty_selection_and_non_builtin_containers():
    class StringSubclass(str):
        pass

    class ListSubclass(list):
        pass

    class DictSubclass(dict):
        pass

    records, selection, excluded, hashes = _inputs()
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, [], excluded, hashes)
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(tuple(records), selection, excluded, hashes)
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(ListSubclass(records), selection, excluded, hashes)
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, [DictSubclass(selection[0])], excluded, hashes)
    records[0]["evidence_id"] = StringSubclass("ev-project")
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, selection, excluded, hashes)


def test_projection_documents_bind_profile_and_ledger_to_live_receipt():
    profile_id = "prf_" + "7" * 32
    profile_sha256 = "8" * 64
    evidence_ledger_sha256 = "9" * 64
    activation_sha256 = "a" * 64
    source_hashes = {
        "recovery_manifest": "b" * 64,
        "profile": "c" * 64,
        "evidence": "d" * 64,
    }
    records = [
        {
            "evidence_id": "ev-project",
            "kind": "project",
            "claim": "A supported synthetic project statement.",
            "status": "verified",
        }
    ]
    selection = [
        {
            "evidence_id": "ev-project",
            "proof_class": "work_artifact",
            "document_targets": ["cv"],
        }
    ]
    packet_bytes, bindings = compile_selected_facts(
        records, selection, [], source_hashes
    )
    original_inputs = deepcopy(
        (records, selection, bindings, source_hashes)
    )

    documents = serialize_projection_documents(
        profile_id=profile_id,
        activation_sha256=activation_sha256,
        packet_bytes=packet_bytes,
        bindings=bindings,
        source_hashes=source_hashes,
        profile_sha256=profile_sha256,
        evidence_ledger_sha256=evidence_ledger_sha256,
    )

    assert (records, selection, bindings, source_hashes) == original_inputs
    authority = json.loads(documents["candidate_authority_bytes"])
    projection = json.loads(documents["candidate_projection_bytes"])
    receipt = json.loads(documents["profile_projection_receipt_bytes"])
    assert authority["profile_binding"] == {
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "evidence_ledger_sha256": evidence_ledger_sha256,
    }
    assert authority["application_authority"] is False
    assert authority["release_authority"] is False
    assert authority["submission_authority"] is False
    assert projection["source_hashes"]["profile"] == source_hashes["profile"]
    assert projection["source_hashes"]["evidence"] == source_hashes["evidence"]
    assert authority["profile_binding"]["profile_sha256"] == profile_sha256
    assert authority["profile_binding"]["evidence_ledger_sha256"] == evidence_ledger_sha256
    validate_current_profile_binding(
        receipt,
        authority,
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        evidence_ledger_sha256=evidence_ledger_sha256,
    )
    validated = validate_current_profile_projection_receipt(
        documents["profile_projection_receipt_bytes"],
        profile_id=profile_id,
        activation_sha256=activation_sha256,
        evidence_packet_bytes=packet_bytes,
        candidate_projection_bytes=documents["candidate_projection_bytes"],
        candidate_authority_bytes=documents["candidate_authority_bytes"],
        profile_sha256=profile_sha256,
        evidence_ledger_sha256=evidence_ledger_sha256,
    )
    assert validated == receipt
    tampered_packet = json.loads(packet_bytes)
    tampered_packet["statements"][0]["statement"] += " altered"
    tampered_packet_bytes = (
        json.dumps(
            tampered_packet,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    tampered_receipt = dict(receipt)
    tampered_receipt["evidence_packet_sha256"] = hashlib.sha256(
        tampered_packet_bytes
    ).hexdigest()
    tampered_receipt_bytes = (
        json.dumps(
            tampered_receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    with pytest.raises(
        ValueError, match="^current_profile_projection_receipt_invalid$"
    ):
        validate_current_profile_projection_receipt(
            tampered_receipt_bytes,
            profile_id=profile_id,
            activation_sha256=activation_sha256,
            evidence_packet_bytes=tampered_packet_bytes,
            candidate_projection_bytes=documents["candidate_projection_bytes"],
            candidate_authority_bytes=documents["candidate_authority_bytes"],
            profile_sha256=profile_sha256,
            evidence_ledger_sha256=evidence_ledger_sha256,
        )
    for source_key in ("recovery_manifest", "profile", "evidence"):
        mismatched_projection = deepcopy(projection)
        mismatched_projection["source_hashes"][source_key] = "a" * 64
        projection_body = dict(mismatched_projection)
        projection_body.pop("projection_sha256")
        projection_sha256 = hashlib.sha256(
            (
                json.dumps(
                    projection_body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        ).hexdigest()
        mismatched_projection["projection_sha256"] = projection_sha256
        mismatched_projection_bytes = (
            json.dumps(
                mismatched_projection,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        mismatched_authority = deepcopy(authority)
        mismatched_authority["candidate_projection"] = mismatched_projection
        mismatched_authority_bytes = (
            json.dumps(
                mismatched_authority,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        mismatched_receipt = dict(receipt)
        mismatched_receipt["authority_sha256"] = hashlib.sha256(
            mismatched_authority_bytes
        ).hexdigest()
        mismatched_receipt["authority_projection_sha256"] = projection_sha256
        mismatched_receipt_bytes = (
            json.dumps(
                mismatched_receipt,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with pytest.raises(
            ValueError, match="^current_profile_projection_receipt_invalid$"
        ):
            validate_current_profile_projection_receipt(
                mismatched_receipt_bytes,
                profile_id=profile_id,
                activation_sha256=activation_sha256,
                evidence_packet_bytes=packet_bytes,
                candidate_projection_bytes=mismatched_projection_bytes,
                candidate_authority_bytes=mismatched_authority_bytes,
                profile_sha256=profile_sha256,
                evidence_ledger_sha256=evidence_ledger_sha256,
            )
    for field, replacement in (
        ("profile_id", "prf_" + "6" * 32),
        ("profile_sha256", "e" * 64),
        ("evidence_ledger_sha256", "f" * 64),
    ):
        tampered_receipt = deepcopy(receipt)
        tampered_receipt[field] = replacement
        with pytest.raises(ValueError, match="^current_profile_binding_invalid$"):
            validate_current_profile_binding(
                tampered_receipt,
                authority,
                profile_id=profile_id,
                profile_sha256=profile_sha256,
                evidence_ledger_sha256=evidence_ledger_sha256,
            )
    with pytest.raises(ValueError, match="^current_profile_binding_invalid$"):
        validate_current_profile_binding(
            receipt,
            authority,
            profile_id=profile_id,
            profile_sha256="e" * 64,
            evidence_ledger_sha256=evidence_ledger_sha256,
        )
    with pytest.raises(ValueError, match="^current_profile_projection_receipt_invalid$"):
        validate_current_profile_projection_receipt(
            documents["profile_projection_receipt_bytes"],
            profile_id=profile_id,
            activation_sha256=activation_sha256,
            evidence_packet_bytes=packet_bytes,
            candidate_projection_bytes=documents["candidate_projection_bytes"],
            candidate_authority_bytes=documents["candidate_authority_bytes"],
            profile_sha256="e" * 64,
            evidence_ledger_sha256=evidence_ledger_sha256,
        )


def test_current_profile_binding_rejects_dict_subclasses():
    class DictSubclass(dict):
        pass

    profile_id = "prf_" + "7" * 32
    source_hashes = {
        "recovery_manifest": "b" * 64,
        "profile": "c" * 64,
        "evidence": "d" * 64,
    }
    records = [
        {
            "evidence_id": "ev-project",
            "kind": "project",
            "claim": "A supported synthetic project statement.",
            "status": "verified",
        }
    ]
    packet_bytes, bindings = compile_selected_facts(
        records,
        [
            {
                "evidence_id": "ev-project",
                "proof_class": "work_artifact",
                "document_targets": ["cv"],
            }
        ],
        [],
        source_hashes,
    )
    documents = serialize_projection_documents(
        profile_id=profile_id,
        activation_sha256="a" * 64,
        packet_bytes=packet_bytes,
        bindings=bindings,
        source_hashes=source_hashes,
        profile_sha256="8" * 64,
        evidence_ledger_sha256="9" * 64,
    )
    authority = json.loads(documents["candidate_authority_bytes"])
    receipt = json.loads(documents["profile_projection_receipt_bytes"])
    with pytest.raises(ValueError, match="^current_profile_binding_invalid$"):
        validate_current_profile_binding(
            DictSubclass(receipt),
            authority,
            profile_id=profile_id,
            profile_sha256="8" * 64,
            evidence_ledger_sha256="9" * 64,
        )
    authority["profile_binding"] = DictSubclass(authority["profile_binding"])
    with pytest.raises(ValueError, match="^current_profile_binding_invalid$"):
        validate_current_profile_binding(
            receipt,
            authority,
            profile_id=profile_id,
            profile_sha256="8" * 64,
            evidence_ledger_sha256="9" * 64,
        )
    records, selection, excluded, hashes = _inputs()
    selection[0]["evidence_id"] = []
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, selection, excluded, hashes)
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, selection, excluded, dict(hashes, extra="d" * 64))
    records, selection, excluded, hashes = _inputs()
    records[0]["claim"] = "invalid \ud800 text"
    with pytest.raises(ValueError, match="^current_fact_packet_invalid$"):
        compile_selected_facts(records, selection, excluded, hashes)
