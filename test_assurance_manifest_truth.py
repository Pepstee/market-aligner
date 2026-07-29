"""Truth controls for slice status and external JAA-04 runtime state."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import yaml

from career_automation.shadow_certification import MUTATION_TEST_NODES
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
    assert (
        jaa09["increment"]
        == "implementation_complete_pending_fable_ratification"
    )
    assert jaa09["evidence"] == []
    assert "one genuine JAA-08 token" in jaa09["claim"]
    assert (
        jaa09["provisional_acceptance"]
        == {
            "status": (
                "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION"
            ),
            "independent_fable_certification": (
                "absent_pending_ratification"
            ),
            "implemented_source_git_revision": (
                "ccc1d14bb65c7f3654359d6b4e08939c524b3161"
            ),
            "implemented_source_tree": (
                "f10b49a80f9a6b3d54647b706fa749d0f74b9a5a"
            ),
            "implemented_source_content_revision": (
                "sha256:3dcc1e030941645115ec5956e56bf1825"
                "de406c1b0d2a8b8c337d60cb7389621"
            ),
            "deputy_authority": {
                "path_base": "software_factory_root",
                "relative_path": (
                    "giga-user/reports/"
                    "JAA_SOL_DEPUTY_AUTHORITY_2026-07-29.md"
                ),
                "sha256": (
                    "8199c4848468669dd908eff8f4b92226d"
                    "f11b82831baf04fd9e663cabc462ef3"
                ),
            },
            "provisional_acceptance_receipt": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "SOL_JAA09_PROVISIONAL_IMPLEMENTATION_ACCEPTANCE.md"
                ),
                "sha256": (
                    "a24b616d23e781c8a7cea29f03e3418ca"
                    "ae2c77ca7092bc3ad5c1bd079e1c728"
                ),
            },
            "sonnet_post_repair_review": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "sonnet-jaa09-sol-deputy-post-repair-review-raw.json"
                ),
                "sha256": (
                    "e77be399d983cfb795b758e0d07b37848"
                    "bc72754d069cc8a0f223bdc8a1613ea"
                ),
            },
            "positive_log": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "jaa09-sol-deputy-post-review-positive.log"
                ),
                "sha256": (
                    "77c0c7d21cb7c859206f08759e24213de"
                    "d843104e55f3b57fb019672a6ecdc40"
                ),
            },
            "negative_restart_log": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "jaa09-sol-deputy-post-review-negative.log"
                ),
                "sha256": (
                    "8f51e13f65eae64d0267cac2efaf8980f"
                    "a226c33f74c56da740ed1bfbbb58fa7"
                ),
            },
            "jaa08_cross_slice_log": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "jaa09-sol-deputy-post-review-jaa08-cross-slice.log"
                ),
                "sha256": (
                    "bc3231ddc0a9050c98b96810c589d4670"
                    "979466779d28a2a54f972380a22070e"
                ),
            },
            "ruff_log": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "jaa09-sol-deputy-post-review-ruff.log"
                ),
                "sha256": (
                    "82b3e6a6c090a57601d22943bd23fca9"
                    "218d1031dbe5a7b754092f9a156b4f18"
                ),
            },
        }
    )
    assert "certification" not in jaa09
    evidence_bases = {
        "operator_control_root": ROOT.parents[1] / ".control",
        "software_factory_root": ROOT.parents[1],
    }
    for key in (
        "deputy_authority",
        "provisional_acceptance_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_restart_log",
        "jaa08_cross_slice_log",
        "ruff_log",
    ):
        pointer = jaa09["provisional_acceptance"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
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
    assert (
        jaa10["increment"]
        == "implementation_complete_pending_fable_ratification"
    )
    assert jaa10["evidence"] == []
    assert "production certification is withheld" in jaa10["claim"]
    assert "all five submit interruption windows" in jaa10["claim"]
    assert (
        "exact fourteen-control executable mutation cohort passes"
        in jaa10["claim"]
    )
    assert jaa10["provisional_acceptance"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_certification": "absent_pending_ratification",
        "implemented_source_git_revision": (
            "43c3d90193e6092b430fdc59cacd7244caaf720b"
        ),
        "implemented_source_tree": (
            "283a1c1051d2ced9bbbecc7eb446dcd5dafe592a"
        ),
        "implemented_source_content_revision": (
            "sha256:8962b3f02120e0b0b88b8584f0e00a7b"
            "e56a101fd0148d323010cc124be73bef"
        ),
        "production_certification": "withheld",
        "deputy_authority": {
            "path_base": "software_factory_root",
            "relative_path": (
                "giga-user/reports/"
                "JAA_SOL_DEPUTY_AUTHORITY_2026-07-29.md"
            ),
            "sha256": (
                "8199c4848468669dd908eff8f4b92226d"
                "f11b82831baf04fd9e663cabc462ef3"
            ),
        },
        "provisional_acceptance_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA10_PROVISIONAL_IMPLEMENTATION_ACCEPTANCE.md"
            ),
            "sha256": (
                "1508876b4a8ccffa2fde26c16a0c821c5"
                "0c6ef978d436ae987e4f855a40f23d5"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-sol-deputy-post-repair-review-raw.json"
            ),
            "sha256": (
                "3d5e484d17b60dd8d43f8074e282b27c"
                "b4570e855d2fd99f74457a626db68a6f"
            ),
        },
        "focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-post-review-focused.log"
            ),
            "sha256": (
                "be3607d83f81b4e789380faa09b522325"
                "efb938c6bfab6dab70cb4c8ee48041e"
            ),
        },
        "mutation_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-mutation-cohort.log"
            ),
            "sha256": (
                "c964f2e41db90c718ffb4d189dd10f3a"
                "0ec82af05bd0bd3bd12fb85afcaf1b40"
            ),
        },
        "jaa09_restart_cross_slice_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-jaa09-restart-cross-slice.log"
            ),
            "sha256": (
                "ffee8a9701562fced0cff6b402682cb53"
                "87cb3f43ec696732232c80ab1f04711"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa10-post-review-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
    }
    assert "certification" not in jaa10
    for key in (
        "deputy_authority",
        "provisional_acceptance_receipt",
        "sonnet_post_repair_review",
        "focused_log",
        "mutation_log",
        "jaa09_restart_cross_slice_log",
        "ruff_log",
    ):
        pointer = jaa10["provisional_acceptance"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    mutation_tests = [
        test for test in jaa10["tests"]
        if test["id"] == "JAA-10-mutation-cohort"
    ]
    assert len(mutation_tests) == 1
    assert mutation_tests[0]["argv"][4:] == list(
        MUTATION_TEST_NODES.values()
    )
    assert mutation_tests[0]["files"] == [
        "test_jaa07_negative_controls.py",
        "test_jaa08_negative_controls.py",
        "test_jaa09_negative_controls.py",
        "test_jaa10_negative_controls.py",
    ]
    for relative in jaa10["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-10 materialised path missing: {relative}"
        )
    for test in jaa10["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-10 declared test missing: {relative}"
            )

    jaa11 = components["JAA-11"]
    assert (
        jaa11["increment"]
        == "fixture_contract_complete_live_canary_withheld"
    )
    assert jaa11["claim"] == executable_slices["JAA-11"]["objective"]
    assert jaa11["depends_on"] == executable_slices["JAA-11"]["depends_on"]
    assert jaa11["provisional_fixture_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": "absent_pending_ratification",
        "implemented_source_git_revision": (
            "4ee1b6a0b9cbd54bf884a22c99783b69ee849f35"
        ),
        "implemented_source_tree": (
            "3bfa4ff3e1f52a02b68e1bdec9e99ca555855f0f"
        ),
        "implemented_source_content_revision": (
            "sha256:d569686f3771e45c10e014e1d26093943"
            "0f62f337a25dc151732e006f51797ae"
        ),
        "target_ats_selected": False,
        "live_canary_status": "not_collected",
        "real_submission_authority": "withheld",
        "production_certification": "withheld",
        "dependency_satisfied": False,
        "deputy_authority": {
            "path_base": "software_factory_root",
            "relative_path": (
                "giga-user/reports/"
                "JAA_SOL_DEPUTY_AUTHORITY_2026-07-29.md"
            ),
            "sha256": (
                "8199c4848468669dd908eff8f4b92226d"
                "f11b82831baf04fd9e663cabc462ef3"
            ),
        },
        "provisional_fixture_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA11_PROVISIONAL_FIXTURE_CONTRACT_ACCEPTANCE.md"
            ),
            "sha256": (
                "5b8c827d6bd94f5a8cddc54ec3387b86"
                "ab748fd7d76d8e2b1fc3755e6e16f4cd"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa11-post-repair-review-raw.json"
            ),
            "sha256": (
                "15fd4d7df2f97130ce91529da3ef5cf2d"
                "1d7efe78c5e14085cc77075a91960b1"
            ),
        },
        "positive_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa11-post-review-positive.log"
            ),
            "sha256": (
                "452fada82e1df58d7f89fa99128aea691"
                "c519ad7daf4915a4bece62bd06ecbdf"
            ),
        },
        "negative_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa11-post-review-negative.log"
            ),
            "sha256": (
                "f5c48f0aec40c7b769a4203fd6fdd7f8"
                "1573cc8be100a125c28d5a0e6c52cd63"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa11-post-review-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
    }
    assert "certification" not in jaa11
    for key in (
        "deputy_authority",
        "provisional_fixture_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_log",
        "ruff_log",
    ):
        pointer = jaa11["provisional_fixture_contract"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert jaa11["evidence"] == [
        {
            "kind": "live_canary",
            "scope": "JAA-11-live-canary",
            "required": True,
            "status": "not_collected",
            "external_action_gate": "explicit_operator_approval_required",
            "max_age_seconds": 86400,
        }
    ]
    for relative in jaa11["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-11 materialised path missing: {relative}"
        )
    for test in jaa11["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-11 declared test missing: {relative}"
            )

    jaa12 = components["JAA-12"]
    assert (
        jaa12["increment"]
        == "local_export_contract_complete_dependency_and_connectors_withheld"
    )
    assert jaa12["claim"] == executable_slices["JAA-12"]["objective"]
    assert jaa12["depends_on"] == executable_slices["JAA-12"]["depends_on"]
    assert jaa12["provisional_local_export_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": "absent_pending_ratification",
        "implemented_source_git_revision": (
            "21ee76bfe5e886e8bc1230a24010b1d841882509"
        ),
        "implemented_source_tree": (
            "6a66f606efa38112701d76a4406bfbcd8180be40"
        ),
        "implemented_source_content_revision": (
            "sha256:4efcdbc108aaea487bb6305dcd370213f7"
            "7969085e33ec8e7f6d0cd505fb723d"
        ),
        "upstream_dependency_satisfied": False,
        "mailbox_connector_status": "not_connected",
        "portal_connector_status": "not_connected",
        "message_send_authority": "withheld",
        "production_certification": "withheld",
        "dependency_satisfied": False,
        "deputy_authority": {
            "path_base": "software_factory_root",
            "relative_path": (
                "giga-user/reports/"
                "JAA_SOL_DEPUTY_AUTHORITY_2026-07-29.md"
            ),
            "sha256": (
                "8199c4848468669dd908eff8f4b92226d"
                "f11b82831baf04fd9e663cabc462ef3"
            ),
        },
        "provisional_local_export_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_PROVISIONAL_LOCAL_EXPORT_CONTRACT_ACCEPTANCE.md"
            ),
            "sha256": (
                "4684e3b09e3d19eac8cacabc1c4adb35"
                "d57e0c6bae451dbc93fa10376d37f97d"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa12-post-repair-review-raw.json"
            ),
            "sha256": (
                "e572ae7d5e0ec8db9a0621e6f363c731"
                "3a0400b3f7cd8235de0094e9c9c99f95"
            ),
        },
        "positive_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa12-post-review-positive.log"
            ),
            "sha256": (
                "dd16cbdbb2cff39a7ff41edae14420833"
                "d1d368adba1f7523723a58e363ea28d"
            ),
        },
        "negative_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa12-post-review-negative.log"
            ),
            "sha256": (
                "1e326b4f56c3766bd4e38495df7fea6e"
                "a9e0b23f9971d64cfceec7a3baad0290"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa12-post-review-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
    }
    assert "certification" not in jaa12
    for key in (
        "deputy_authority",
        "provisional_local_export_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_log",
        "ruff_log",
    ):
        pointer = jaa12["provisional_local_export_contract"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert jaa12["evidence"] == []
    for relative in jaa12["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-12 materialised path missing: {relative}"
        )
    for test in jaa12["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-12 declared test missing: {relative}"
            )

    for number in range(13, 17):
        slice_id = f"JAA-{number:02d}"
        component = components[slice_id]
        assert component["increment"] == "not_implemented"
        assert component["claim"] == executable_slices[slice_id]["objective"]
        assert component["depends_on"] == executable_slices[slice_id]["depends_on"]
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
