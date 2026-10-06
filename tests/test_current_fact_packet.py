from __future__ import annotations

import hashlib
import json

import pytest

from market_aligner.profiler.fact_packet import compile_selected_facts


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
