"""Truth controls for slice status and external JAA-04 runtime state."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from tracked_source_revision import source_git_revision


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "ASSURANCE_MANIFEST.json"
SLICES = ROOT / "IMPLEMENTATION_SLICES.yaml"


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_unimplemented_slices_are_not_declared_complete() -> None:
    components = _manifest()["components"]
    executable_slices = {
        item["id"]: item
        for item in yaml.safe_load(SLICES.read_text(encoding="utf-8"))["slices"]
    }
    jaa05 = components["JAA-05"]
    assert jaa05["increment"] == "human_evidence_ingested_production_receipted"
    assert jaa05["certification"] == {
        "status": "certified_implementation",
        "certified_source_git_revision": (
            "894484336111913ea728985f13e1dbfed35448fd"
        ),
        "certified_source_tree": (
            "bf37e9cd9e2ee1c7c4fdbdc963c11622f4826c20"
        ),
        "certified_source_content_revision": (
            "sha256:51294567a7bfe20b348c97c19ddef46"
            "c9614d64264f08e02f4a3b0007a7217ef"
        ),
        "rule": (
            "Models may discover and questionnaire candidate claims but must "
            "not create, edit, normalise or approve production candidate evidence."
        ),
        "private_evidence_sha256": (
            "7a7e18a686b0979e48716f983871568e"
            "018c04398e05b8c71af88059f6fb6195"
        ),
        "human_authority_sha256": (
            "9cb26a0478b64bf8c5b63c602e7ad454"
            "cc79d2d4a81e93d4d3298ac7046c207b"
        ),
        "source_packet_sha256": (
            "6ee3cc29b2074b4244686ca938028ad3"
            "97ca0a39ab6323de59b52eb20d6eadb7"
        ),
        "file_sha256": (
            "71deaaadcc7498f77204e5ff9e96679f"
            "35ce181a67e78b585c46fb2b6821878d"
        ),
        "projection_sha256": (
            "82ba6ca979b66fea25b1e987c50b8cdb"
            "beca746869d0563a24480892c7ddab00"
        ),
        "production_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-current-supervisor-20260728/"
                "jaa05-production-ingestion-8944843/"
                "sha256-0980278bca34b851ff6208e5317cd80306f88a6b"
                "1496db2c8e4af1e618b00228.json"
            ),
            "sha256": (
                "0980278bca34b851ff6208e5317cd803"
                "06f88a6b1496db2c8e4af1e618b00228"
            ),
        },
        "entry_fable_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-current-supervisor-20260728/"
                "fable-jaa05-entry-certification-raw.json"
            ),
            "sha256": (
                "72d5197e4283f61226316900d41c0d7b"
                "199ad023fa2c837fe8ac396ce4ffa7d0"
            ),
        },
        "sonnet_bounded_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-current-supervisor-20260728/"
                "sonnet-jaa05-bounded-repair-review-raw.json"
            ),
            "sha256": (
                "9954f5ef6294689a7274d30c12de4cd5"
                "92323c208ff3a8301148d80c63ea175c"
            ),
        },
        "implementation_certification_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-current-supervisor-20260728/"
                "fable-jaa05-exact-source-certification-raw.json"
            ),
            "sha256": (
                "0590955e65f78a66d25108d6b5c8d507"
                "aed2034e3cf96cdec14cd78270fdcf64"
            ),
        },
        "full_regression_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-current-supervisor-20260728/"
                "jaa05-full-regression-8944843.log"
            ),
            "sha256": (
                "d631808a650b395ec337314120bb06583"
                "29b05a021c88a1c2dbb0ba39d58bfd5"
            ),
        },
    }
    for relative in jaa05["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-05 materialised path missing: {relative}"
    for test in jaa05["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-05 declared test missing: {relative}"

    jaa06 = components["JAA-06"]
    assert jaa06["increment"] == "implementation_complete"
    assert jaa06["certification"] == {
        "status": "certified_implementation",
        "certified_source_git_revision": (
            "8c4668a3adc7a2e95a250f1fb07a98b988491abe"
        ),
        "certified_source_tree": (
            "61c3db26e98799a9726dec639a71ed8cde5ebb8e"
        ),
        "certified_source_content_revision": (
            "sha256:e7f77b81907de012217f34d0202f3648"
            "2090bdbf480b313011ec1d2ac5172405"
        ),
        "entry_fable_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa06-entry-gate-resume-raw.json"
            ),
            "sha256": (
                "79e3ffb304b12705987f8093e48af3de"
                "352178e0fde06101dab64632a7ff57a1"
            ),
        },
        "jaa07_cascade_fable_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa06-jaa07-fixture-cascade-raw.json"
            ),
            "sha256": (
                "ab9098a8949bb1da1eef77201f6583bc"
                "b7bea41d374ef7336476ad911a55ef27"
            ),
        },
        "sonnet_bounded_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa06-repair-review-raw.json"
            ),
            "sha256": (
                "cb57d1fd599bb9c8c4ddba2ffa2ae9c6"
                "4fc8cb21945535b99d81fba188157f5e"
            ),
        },
        "implementation_certification_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa06-exact-source-certification-raw.json"
            ),
            "sha256": (
                "56199fece01f33d226292ecebcb0a1db"
                "5f92e99155c273f9c0867569f863c5d6"
            ),
        },
        "focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa06-repair-focused.log"
            ),
            "sha256": (
                "47c00aa23d225b01774294afa4317dd7"
                "bbda1960dfeb655e0ef6f4bffc9067df"
            ),
        },
        "manifest_truth_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa06-repair-manifest-truth.log"
            ),
            "sha256": (
                "f21802e5e24571b06b077e416af1539f"
                "dce6ad55b407e03af6af45b03968cb3b"
            ),
        },
        "locked_evaluator_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa06-repair-locked-evaluator.log"
            ),
            "sha256": (
                "d5ac2ca4dc759c0996d2987a85e38b0"
                "59133799463a02892b76b016a4e7c03ca"
            ),
        },
        "production_projection_integration_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa06-repair-production-projection-integration.log"
            ),
            "sha256": (
                "885e51b9026a99dadc68ff084adfa82d"
                "0a385f6ec2f56b31c77d3e1d924515f0"
            ),
        },
        "jaa07_hash_cascade_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa06-repair-jaa07-hash-cascade.log"
            ),
            "sha256": (
                "6198a1ade99b2f1af4b60bfdc150b317"
                "3fc2028bc0996f6549f044f63dca03e8"
            ),
        },
        "jaa07_evaluator_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa06-repair-jaa07-evaluator.log"
            ),
            "sha256": (
                "5cf1f1f5bcee57aaf8a517edb734cf9d"
                "adf1802e44f831defd105418c41ef1fe"
            ),
        },
        "full_regression_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa06-repair-cross-slice-regression-green.log"
            ),
            "sha256": (
                "6c5c1525b1e9f5be88e63c5694fb42e"
                "4425c8d381a310bf91b50804b1e66f25f"
            ),
        },
    }
    for relative in jaa06["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-06 materialised path missing: {relative}"
    for test in jaa06["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-06 declared test missing: {relative}"

    jaa07 = components["JAA-07"]
    assert jaa07["increment"] == "implementation_complete"
    assert jaa07["certification"] == {
        "status": "certified_implementation",
        "certified_source_git_revision": (
            "8973ae3d473c43eeed397d273ef7088e2217b74b"
        ),
        "certified_source_tree": (
            "428f8c94e5de133e81dfc33e56ac7f32d1797848"
        ),
        "certified_source_content_revision": (
            "sha256:a701e3f0b00d1b2aab602ac2df274992"
            "8fe2f4c741472f4add1131909ece0ea4"
        ),
        "jaa06_authority_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa06-post-finalization-raw.json"
            ),
            "sha256": (
                "81d800b5aa70b3557b723d0023053b4d"
                "bc6a913f05362704d8bfe99e22707aa3"
            ),
        },
        "entry_fable_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa07-entry-gate-ruling.md"
            ),
            "sha256": (
                "560d9116b1180bff650810e9e6a766ad"
                "3c7948cac102352f3a655bca67f02237"
            ),
        },
        "sonnet_exact_head_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa07-exact-head-review-raw.json"
            ),
            "sha256": (
                "d109ae05082d74d9b26e92299fe47c5f"
                "166d4f5baab49ac7ec9ecce8d6f26a74"
            ),
        },
        "implementation_gate_fable_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa07-implementation-gate-raw.json"
            ),
            "sha256": (
                "f3646ff08de5421146ac3ed94ee14b175"
                "77d45265067c79bd1be847ffa598820"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa07-post-repair-review-raw.json"
            ),
            "sha256": (
                "b9e9aaed8222902acee9eadb6d4d8c38"
                "d38113a88c66503661945cd951b735cc"
            ),
        },
        "implementation_certification_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa07-post-repair-certification-raw.json"
            ),
            "sha256": (
                "bdbf82c56b94afd3301d6003e5d6673e"
                "94c8e009be08d1e2692d3528fc2b402c"
            ),
        },
        "focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa07-post-review-repair-focused.log"
            ),
            "sha256": (
                "a8cef484db468214d4b1b439333a4fbfe"
                "3b534c841fe03219d8b8142b946efa8"
            ),
        },
        "cross_slice_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa07-post-review-repair-cross-slice.log"
            ),
            "sha256": (
                "d40086ee7c5ab09afff73766962f8c3a"
                "56f0e612418e691fb91b51c9c0d7ef83"
            ),
        },
        "evaluator_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa07-post-review-repair-evaluator.log"
            ),
            "sha256": (
                "5cf1f1f5bcee57aaf8a517edb734cf9d"
                "adf1802e44f831defd105418c41ef1fe"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa07-post-review-repair-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "full_regression_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa07-finalization-cross-slice-regression-green.log"
            ),
            "sha256": (
                "edfaa02171a0abda58b2a3acd0c73542"
                "fff28be171517101852b9778753369c0"
            ),
        },
    }
    for relative in jaa07["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-07 materialised path missing: {relative}"
    for test in jaa07["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-07 declared test missing: {relative}"

    jaa08 = components["JAA-08"]
    assert jaa08["increment"] == "implementation_complete"
    assert jaa08["certification"] == {
        "status": "certified_implementation",
        "certified_source_git_revision": (
            "00da24fe8e423c1b98b0d8ca1b98d71e691f2bce"
        ),
        "certified_source_tree": (
            "ef1b9089e3527c9c4ad07cd44ba9ec699cf0e46d"
        ),
        "certified_source_content_revision": (
            "sha256:052c9b6b91ed0ccaa2a819575195acebd"
            "1df284ec84dcca2cb35230afb639319"
        ),
        "reconciliation_authority_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa08-reconciliation-gate-ruling.md"
            ),
            "sha256": (
                "f972a52d8ffe23c4c9f6b9aad467def6"
                "997b88c9b0d80bcdaa671616c6008e6b"
            ),
        },
        "sonnet_reconciliation_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa08-reconciliation-review-raw.json"
            ),
            "sha256": (
                "b641ad4db06851510a20892f92ba6c4be"
                "557b57bedb74893950b01958bd0f84b"
            ),
        },
        "focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa08-reconciliation-focused.log"
            ),
            "sha256": (
                "cb9539ec5af489a9fb094d9941c9e1ee9"
                "e0c713a7fcdc99d2ee76c1a09d4165c"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa08-reconciliation-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "implementation_certification_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa08-post-reconciliation-certification-raw.json"
            ),
            "sha256": (
                "d7daa41bdb51fb10a5fbf581373965860"
                "1034971c4524cf690c0764b17a76a4c"
            ),
        },
    }
    assert jaa08["evidence"] == []
    for relative in jaa08["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-08 materialised path missing: {relative}"
    for test in jaa08["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-08 declared test missing: {relative}"

    jaa09 = components["JAA-09"]
    assert jaa09["increment"] == "implementation_in_progress"
    assert jaa09["evidence"] == []
    assert "one genuine JAA-08 token" in jaa09["claim"]
    for relative in jaa09["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-09 materialised path missing: {relative}"
        )
    for test in jaa09["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-09 declared test missing: {relative}"
            )

    jaa10 = components["JAA-10"]
    assert jaa10["increment"] == "implementation_in_progress_dependency_blocked"
    assert jaa10["evidence"] == []
    assert "production certification is withheld" in jaa10["claim"]
    assert "exact seven-control executable mutation cohort passes" in jaa10["claim"]
    mutation_tests = [
        test for test in jaa10["tests"]
        if test["id"] == "JAA-10-mutation-cohort"
    ]
    assert len(mutation_tests) == 1
    assert len(mutation_tests[0]["argv"][4:]) == 7
    for relative in jaa10["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-10 materialised path missing: {relative}"
        )
    for test in jaa10["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-10 declared test missing: {relative}"
            )

    for number in range(11, 17):
        slice_id = f"JAA-{number:02d}"
        component = components[slice_id]
        assert component["increment"] == "not_implemented"
        assert component["claim"] == executable_slices[slice_id]["objective"]
        assert component["depends_on"] == executable_slices[slice_id]["depends_on"]
        if slice_id == "JAA-11":
            assert component["evidence"] == [
                {
                    "kind": "live_canary",
                    "scope": "JAA-11-live-canary",
                    "required": True,
                    "status": "not_collected",
                    "external_action_gate": "explicit_operator_approval_required",
                    "max_age_seconds": 86400,
                }
            ]
        else:
            assert component["evidence"] == []

        # A future declaration cannot become progress merely by changing this
        # status string. Every declared owned path and named slice test is
        # currently absent, matching the truthful starting state.
        for pattern in component["owns"]:
            if not any(token in pattern for token in ("*", "?", "[")):
                assert not (ROOT / pattern).exists(), f"{slice_id} status needs reassessment"
        for test in component["tests"]:
            for relative in test["files"]:
                if slice_id == "JAA-16" and relative == "test_acceptance_declaration_contract.py":
                    continue
                assert not (ROOT / relative).exists(), f"{slice_id} status needs reassessment"


def test_stale_and_incomplete_slice_states_are_explicit() -> None:
    components = _manifest()["components"]
    assert components["JAA-00"]["increment"] == "historical_baseline"
    jaa01 = components["JAA-01"]
    assert jaa01["increment"] == "implementation_complete_current_recertification_blocked"
    historical_receipt = ROOT / jaa01["certification"]["historical_receipt"]
    historical_document = json.loads(historical_receipt.read_text(encoding="utf-8"))
    assert jaa01["certification"] == {
        "status": "historical_receipt_stale",
        "historical_receipt": (
            "runtime_evidence/jaa01/"
            "sha256-a8454e3515c95d73e7dc502016dd1c54bc4e78395c47430bb9fb34f254ec4d84.json"
        ),
        "historical_source_content_revision": (
            "sha256:14eb7db0bc3575eee6854eef4ce0bd729e76d6eee8d20ac261db657f87b7854b"
        ),
        "historical_source_git_revision": "a9f94bcd75213fb0511edf55d7e67256df41f756",
        "current_recertification_blocked_by": "genuine_frozen_jaa00_runtime_unavailable",
        "required_current_scope": [
            "current-tracked-source-tree",
            "exact-source-commit",
        ],
    }
    assert (
        historical_document["source_content_revision"]
        == jaa01["certification"]["historical_source_content_revision"]
    )
    assert (
        historical_document["source_git_revision"]
        == jaa01["certification"]["historical_source_git_revision"]
    )
    assert historical_document["source_git_revision"] != source_git_revision(ROOT)
    current_receipt_tests = [
        test for test in jaa01["tests"]
        if test["id"] == "JAA-01-current-receipt"
    ]
    assert current_receipt_tests == [
        {
            "id": "JAA-01-current-receipt",
            "argv": [
                "{python}",
                "-m",
                "pytest",
                "-q",
                "test_jaa01_checked_receipt_current_revision.py",
            ],
            "files": ["test_jaa01_checked_receipt_current_revision.py"],
        }
    ]
    assert jaa01["evidence"] == [
        {
            "kind": "frozen_runtime",
            "scope": "JAA-01-current-runtime",
            "required": True,
            "tracked": False,
        }
    ]
    assert components["JAA-02"]["increment"] == "complete"
    assert components["JAA-03"]["increment"] == "complete"
    jaa04 = components["JAA-04"]
    assert jaa04["increment"] == "complete"
    assert jaa04["certification"] == {
        "status": "independently_certified",
        "certified_source_git_revision": "a4f44905323abd21f926341e35263a478d381cf4",
        "corpus_inventory_sha256": "f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258",
        "receipt": "sha256-69299c7d8bac80bcd2b73a85069e80ba433ef75d6092349384f2dd6cdaff418b.json",
        "independent_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-12h-supervisor-20260727/evidence/"
                "round-09-fable-jaa04-final-certification-ruling.json"
            ),
            "sha256": (
                "62ffda62500184b03b53eb3c61d6a0ee"
                "3f66beda6f63f5501355c6d9746c5b53"
            ),
        },
        "note": "This certification supersedes the stale increment_b_incomplete manifest state.",
    }


def test_jaa04_inflight_databases_and_response_bytes_are_untracked() -> None:
    tracked = subprocess.run(
        ("git", "ls-files", "-z", "--", "runtime_evidence/jaa04/inflight"),
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    assert tracked == b""
    ignored = subprocess.run(
        (
            "git", "check-ignore", "--quiet", "--no-index",
            "runtime_evidence/jaa04/inflight/queue.sqlite3",
        ),
        cwd=ROOT,
        check=False,
    )
    assert ignored.returncode == 0
