"""Truth controls for slice status and external JAA-04 runtime state."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import yaml

from career_automation.shadow_certification import MUTATION_TEST_NODES
from tracked_source_revision import (
    SOURCE_CONTENT_REVISION_DOMAIN,
    source_git_revision,
)


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "ASSURANCE_MANIFEST.json"
SLICES = ROOT / "IMPLEMENTATION_SLICES.yaml"


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _source_content_revision_at(revision: str) -> str:
    entries: list[tuple[bytes, bytes, bytes]] = []
    for record in _git(
        "ls-tree", "-r", "-z", "--full-tree", revision
    ).split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        mode, object_type, object_id = metadata.split()
        assert separator and object_type == b"blob"
        if path.startswith(b"runtime_evidence/"):
            continue
        entries.append((path, mode, _git("cat-file", "blob", object_id.decode())))
    digest = hashlib.sha256(SOURCE_CONTENT_REVISION_DOMAIN)
    for path, mode, payload in sorted(entries):
        for field in (path, mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return f"sha256:{digest.hexdigest()}"


def _declared_slice_paths(component: dict[str, object]) -> list[str]:
    declared = [
        *component["owns"],
        *component["inputs"],
        *component["interfaces"],
        *component["environment"],
    ]
    declared.extend(
        relative
        for test in component["tests"]
        for relative in test["files"]
    )
    expanded: set[str] = set()
    for relative in declared:
        pathspec = relative[:-3] if relative.endswith("/**") else relative
        expanded.update(
            _git(
                "ls-tree", "-r", "--name-only", "HEAD", "--", pathspec
            ).decode().splitlines()
        )
    return sorted(expanded)


def _evidence_pointers(value: object) -> Iterator[dict[str, str]]:
    if isinstance(value, dict):
        if set(value) == {"path_base", "relative_path", "sha256"}:
            yield value
            return
        for nested in value.values():
            yield from _evidence_pointers(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _evidence_pointers(nested)


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
        == "local_fixture_boundary_certified_with_real_frozen_vacancy_input"
    )
    assert jaa09["evidence"] == [
        {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa09-real-vacancy-local-receipt-sha256-"
                "d19e884285c31d08d5cee8276cf197f7903c3a07bd0760f19aef5286fb01140c"
                ".json"
            ),
            "sha256": (
                "d19e884285c31d08d5cee8276cf197f7903c3a07bd0760f19aef5286fb01140c"
            ),
        }
    ]
    assert "one genuine JAA-08 token" in jaa09["claim"]
    assert "provisional_acceptance" not in jaa09
    assert "objective_satisfied" not in jaa09
    assert jaa09["certification"] == {
        "status": "certified_local_fixture_boundary_implementation",
        "certified_source_git_revision": (
            "7f2acfcfddb7c1f66af6a63dd7cb52a3762f54a8"
        ),
        "certified_source_tree": (
            "3d4df58429daa7e97310552c8556945720627915"
        ),
        "certified_source_content_revision": (
            "sha256:eceb58ce3ac49025fb4e0ee65ff7cc4d"
            "a4906e8d74241b7a1ec04d2e481db95a"
        ),
        "evidence_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa09-real-vacancy-local-receipt-sha256-"
                "d19e884285c31d08d5cee8276cf197f7903c3a07bd0760f19aef5286fb01140c"
                ".json"
            ),
            "sha256": (
                "d19e884285c31d08d5cee8276cf197f7903c3a07bd0760f19aef5286fb01140c"
            ),
        },
        "phase_a_acceptance_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa09-real-vacancy-phase-a-acceptance-raw.json"
            ),
            "sha256": (
                "bb6524d17937a540d76688539ea6b7095"
                "ea8bcf57870bb23647d6817ed56e657"
            ),
        },
        "sonnet_phase_b_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa09-real-vacancy-phase-b-review-raw.json"
            ),
            "sha256": (
                "df682079a815dbddf49d25a869cf82df1"
                "a07d2f553b3a56692a5bbafecef6120"
            ),
        },
        "final_certification_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa09-real-vacancy-phase-b-final-ruling-raw.json"
            ),
            "sha256": (
                "9804b6adfbb6319229f3a5ae8858da2a7"
                "c86147bd1d8b8dcd4061fc01f790df5"
            ),
        },
    }
    evidence_bases = {
        "operator_control_root": ROOT.parents[1] / ".control",
        "software_factory_root": ROOT.parents[1],
    }
    assert (
        jaa09["certification"]["evidence_receipt"]
        == jaa09["evidence"][0]
    )
    for key in (
        "evidence_receipt",
        "phase_a_acceptance_ruling",
        "sonnet_phase_b_review",
        "final_certification_ruling",
    ):
        pointer = jaa09["certification"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    certified_revision = jaa09["certification"][
        "certified_source_git_revision"
    ]
    certified_tree = jaa09["certification"]["certified_source_tree"]
    certified_content = jaa09["certification"][
        "certified_source_content_revision"
    ]
    assert _git(
        "rev-parse",
        f"{certified_revision}^{{tree}}",
    ).decode().strip() == certified_tree
    assert subprocess.run(
        ("git", "merge-base", "--is-ancestor", certified_revision, "HEAD"),
        cwd=ROOT,
        check=False,
    ).returncode == 0
    assert _source_content_revision_at(certified_revision) == certified_content
    for relative in _declared_slice_paths(jaa09):
        assert _git(
            "rev-parse",
            f"{certified_revision}:{relative}",
        ) == _git("rev-parse", f"HEAD:{relative}")
    tests_by_id = {test["id"]: test for test in jaa09["tests"]}
    assert tests_by_id["JAA-09-real-vacancy-browser"]["files"] == [
        "test_jaa09_real_vacancy_acceptance.py"
    ]
    assert tests_by_id[
        "JAA-09-real-vacancy-negative-controls"
    ]["files"] == ["test_jaa09_real_vacancy_negative_controls.py"]
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
        == (
            "canonical_contract_negative_control_added_"
            "bounded_local_accepted"
        )
    )
    assert jaa10["objective_satisfied"] is False
    assert jaa10["evidence"] == []
    assert (
        "verified real-frozen-vacancy input rebased onto the standing "
        "JAA-09 certified source"
    ) in jaa10["claim"]
    assert (
        "production certification is withheld with reason "
        "live_time_separated_shadow_and_metrics_not_evaluated"
    ) in jaa10["claim"]
    assert (
        "self-consistent alternative frozen-shadow-contract negative control "
        "proves both the compile-path and verify-path canonical-contract "
        "barriers reject non-canonical contracts"
    ) in jaa10["claim"]
    assert "all five submit interruption windows" in jaa10["claim"]
    assert (
        "exact fourteen-control executable mutation cohort passes"
        in jaa10["claim"]
    )
    assert jaa10["bounded_local_acceptance"] == {
        "status": (
            "INDEPENDENT_FABLE_BOUNDED_LOCAL_ACCEPTED_"
            "OBJECTIVE_UNSATISFIED"
        ),
        "independent_fable_certification": (
            "real_frozen_vacancy_bounded_local_implementation_with_"
            "canonical_contract_control_independently_accepted_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "a975d7b35cd6dd20d00cc689018b91c71bf5af63"
        ),
        "implemented_source_tree": (
            "fc9cc3f33e9b326a38059d1f0191997813e791d0"
        ),
        "implemented_source_content_revision": (
            "sha256:dcf7f436025e2c273affc352ecc8f43f"
            "841e54fe1f13310f072d170ec416bd3c"
        ),
        "frozen_shadow_baseline": {
            "baseline_revision": (
                "7f2acfcfddb7c1f66af6a63dd7cb52a3762f54a8"
            ),
            "baseline_tree": (
                "3d4df58429daa7e97310552c8556945720627915"
            ),
            "baseline_source_content_revision": (
                "sha256:eceb58ce3ac49025fb4e0ee65ff7cc4d"
                "a4906e8d74241b7a1ec04d2e481db95a"
            ),
            "application_id": "graphcore-build-engineer",
            "job_key": "greenhouse:graphcore:8420314002",
            "corpus_inventory_sha256": (
                "f93733a741ffe9b0441fe4bf549d3bb34"
                "e167d28d90283f70003843805201258"
            ),
            "official_response_sha256": (
                "49097938daa0a352cbbf6e26de54c355d"
                "cc0090060e1fd2fde2288a32d26a061"
            ),
            "dossier_sha256": (
                "bf8692e5977cf20f18b2fe7ba3a19f29"
                "678a21c4b428dd91cf937ac580b8da4a"
            ),
            "frozen_shadow_contract_sha256": (
                "a3af7433808ec9adb787d76b3d29ce0b"
                "e0cd263f53cee34cbdf5cee426f9c01b"
            ),
            "contract_schema_version": "jaa10.frozen-shadow-contract.v2",
            "withheld_evidence_schema_version": (
                "jaa10.withheld-shadow-evidence.v4"
            ),
            "withheld_reason": (
                "live_time_separated_shadow_and_metrics_not_evaluated"
            ),
            "standing_jaa09_real_vacancy_rebased": True,
        },
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
        "sonnet_bounded_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-real-vacancy-rebase-review-raw.json"
            ),
            "sha256": (
                "d6a97f60a1ec7eb9f37cff856d4457ce"
                "11dde983f7999b1892327387b8e6dd49"
            ),
        },
        "bounded_local_gate_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-real-vacancy-rebase-gate-raw.json"
            ),
            "sha256": (
                "f536faf6b0f28bd717611aefbd178eece"
                "0efbfa301137caea9026353611917fe"
            ),
        },
        "canonical_contract_control_targeted_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-canonical-contract-control-targeted.log"
            ),
            "sha256": (
                "fa8e3e1f0a4b084326a7027307e5cc3a"
                "94f799f9733ea598c3b878fa3c70f37c"
            ),
        },
        "canonical_contract_control_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-canonical-contract-control-focused.log"
            ),
            "sha256": (
                "e4c66c8362cecdbac35c568b3c623ab3"
                "f1476473ffd93edd62294556bed76237"
            ),
        },
        "canonical_contract_control_ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-canonical-contract-control-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "canonical_contract_control_stale_truth_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa10-canonical-contract-control-stale-truth.log"
            ),
            "sha256": (
                "d66fe2171e062ab7e2f4b866d8b31fe1"
                "41561c5f25e0883a7641f46cf7df0027"
            ),
        },
        "sonnet_canonical_contract_control_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-canonical-contract-control-review-raw.json"
            ),
            "sha256": (
                "6316cbc7e6ac7a07bbcb2f242ebe1d01"
                "70683e6b2e7b927c7831d1a8b0d75aa4"
            ),
        },
        "canonical_contract_control_gate_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-canonical-contract-control-gate-raw.json"
            ),
            "sha256": (
                "6c54f0cb2959ff43bd9056b456aca2a1"
                "0cce30cd23fca0f96d9cb442503a53c6"
            ),
        },
        "superseded_bounded_local_acceptances": [
            {
                "status": (
                    "INDEPENDENT_FABLE_BOUNDED_LOCAL_ACCEPTED_"
                    "OBJECTIVE_UNSATISFIED"
                ),
                "independent_fable_certification": (
                    "bounded_local_implementation_independently_accepted_"
                    "objective_unsatisfied_2026-07-30"
                ),
                "implemented_source_git_revision": (
                    "82ff3e0931c5c342e4d43b40773950a78e0b32bd"
                ),
                "implemented_source_tree": (
                    "a122a3e820ed21b2c915caabb3a273080abc0e37"
                ),
                "implemented_source_content_revision": (
                    "sha256:e69be3197496efc04bbf178035ee7ec02"
                    "e26b66fa0874924109a814cefdfcf66"
                ),
                "frozen_shadow_baseline": {
                    "baseline_revision": (
                        "8107f09beb3c5651850ad40a0ff8842ac2de1e47"
                    ),
                    "job_key": "jaa06-synthetic:strategy-job",
                    "standing_jaa09_real_vacancy_rebased": False,
                },
                "production_certification": "withheld",
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
                        "jaa-single-codex-20260729/"
                        "jaa10-post-review-ruff.log"
                    ),
                    "sha256": (
                        "82b3e6a6c090a57601d22943bd23fca9"
                        "218d1031dbe5a7b754092f9a156b4f18"
                    ),
                },
                "final_integrity_receipt": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "SOL_JAA10_INTEGRITY_REPAIR_ACCEPTANCE.md"
                    ),
                    "sha256": (
                        "88c848f7f4b2c9af5c69f4d8e9fe3229"
                        "5089570f4816a79abfff82f272f7f98e"
                    ),
                },
                "bounded_local_gate_ruling": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "fable-jaa10-exact-gate-raw.json"
                    ),
                    "sha256": (
                        "46340ed2ab29bf0b379f2a78980339b9d"
                        "7350ee4b17013133967743cd3687dd6"
                    ),
                },
                "truth_transition_receipt": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "JAA10_BOUNDED_LOCAL_TRUTH_TRANSITION.md"
                    ),
                    "sha256": (
                        "82efc72f7ef97bec7b15e3d63dc8ff8a"
                        "661a550296d32e80fb266281a5ccae5b"
                    ),
                },
            },
            {
                "status": (
                    "INDEPENDENT_FABLE_BOUNDED_LOCAL_ACCEPTED_"
                    "OBJECTIVE_UNSATISFIED"
                ),
                "independent_fable_certification": (
                    "real_frozen_vacancy_bounded_local_implementation_"
                    "independently_accepted_objective_unsatisfied_2026-07-30"
                ),
                "implemented_source_git_revision": (
                    "6544fff00f2e825873e91b460c19669114c1bf56"
                ),
                "implemented_source_tree": (
                    "e2dfdc5a6c7f4019c862663333404932be2a4760"
                ),
                "implemented_source_content_revision": (
                    "sha256:be6296205c136f02d5a3d13b123a5f7"
                    "01abc830538375777289e4a610f5052ae"
                ),
                "frozen_shadow_baseline": {
                    "baseline_revision": (
                        "7f2acfcfddb7c1f66af6a63dd7cb52a3762f54a8"
                    ),
                    "baseline_tree": (
                        "3d4df58429daa7e97310552c8556945720627915"
                    ),
                    "baseline_source_content_revision": (
                        "sha256:eceb58ce3ac49025fb4e0ee65ff7cc4d"
                        "a4906e8d74241b7a1ec04d2e481db95a"
                    ),
                    "application_id": "graphcore-build-engineer",
                    "job_key": "greenhouse:graphcore:8420314002",
                    "corpus_inventory_sha256": (
                        "f93733a741ffe9b0441fe4bf549d3bb34"
                        "e167d28d90283f70003843805201258"
                    ),
                    "official_response_sha256": (
                        "49097938daa0a352cbbf6e26de54c355d"
                        "cc0090060e1fd2fde2288a32d26a061"
                    ),
                    "dossier_sha256": (
                        "bf8692e5977cf20f18b2fe7ba3a19f29"
                        "678a21c4b428dd91cf937ac580b8da4a"
                    ),
                    "frozen_shadow_contract_sha256": (
                        "a3af7433808ec9adb787d76b3d29ce0b"
                        "e0cd263f53cee34cbdf5cee426f9c01b"
                    ),
                    "contract_schema_version": (
                        "jaa10.frozen-shadow-contract.v2"
                    ),
                    "withheld_evidence_schema_version": (
                        "jaa10.withheld-shadow-evidence.v4"
                    ),
                    "withheld_reason": (
                        "live_time_separated_shadow_and_metrics_not_evaluated"
                    ),
                    "standing_jaa09_real_vacancy_rebased": True,
                },
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
                "sonnet_bounded_review": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "sonnet-jaa10-real-vacancy-rebase-review-raw.json"
                    ),
                    "sha256": (
                        "d6a97f60a1ec7eb9f37cff856d4457ce"
                        "11dde983f7999b1892327387b8e6dd49"
                    ),
                },
                "bounded_local_gate_ruling": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "fable-jaa10-real-vacancy-rebase-gate-raw.json"
                    ),
                    "sha256": (
                        "f536faf6b0f28bd717611aefbd178eece"
                        "0efbfa301137caea9026353611917fe"
                    ),
                },
                "truth_transition_receipt": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "FABLE_JAA10_REAL_VACANCY_"
                        "BOUNDED_LOCAL_TRUTH_TRANSITION.md"
                    ),
                    "sha256": (
                        "eda5a61c5ca6049a8f97034f057275856"
                        "bfb64402b14fac6085294790b1e6734"
                    ),
                },
            }
        ],
    }
    assert "certification" not in jaa10
    for key in (
        "deputy_authority",
        "sonnet_bounded_review",
        "bounded_local_gate_ruling",
        "canonical_contract_control_targeted_log",
        "canonical_contract_control_focused_log",
        "canonical_contract_control_ruff_log",
        "canonical_contract_control_stale_truth_log",
        "sonnet_canonical_contract_control_review",
        "canonical_contract_control_gate_ruling",
    ):
        pointer = jaa10["bounded_local_acceptance"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    history = jaa10["bounded_local_acceptance"][
        "superseded_bounded_local_acceptances"
    ]
    expected_history = (
        (
            "82ff3e0931c5c342e4d43b40773950a78e0b32bd",
            "a122a3e820ed21b2c915caabb3a273080abc0e37",
            "sha256:e69be3197496efc04bbf178035ee7ec0"
            "2e26b66fa0874924109a814cefdfcf66",
            "bounded_local_implementation_independently_accepted_"
            "objective_unsatisfied_2026-07-30",
        ),
        (
            "6544fff00f2e825873e91b460c19669114c1bf56",
            "e2dfdc5a6c7f4019c862663333404932be2a4760",
            "sha256:be6296205c136f02d5a3d13b123a5f7"
            "01abc830538375777289e4a610f5052ae",
            "real_frozen_vacancy_bounded_local_implementation_"
            "independently_accepted_objective_unsatisfied_2026-07-30",
        ),
    )
    assert len(history) == len(expected_history)
    for old_acceptance, expected in zip(
        history, expected_history, strict=True
    ):
        old_revision, old_tree, old_content_revision, old_marker = expected
        assert old_acceptance["implemented_source_git_revision"] == (
            old_revision
        )
        assert old_acceptance["implemented_source_tree"] == old_tree
        assert old_acceptance["implemented_source_content_revision"] == (
            old_content_revision
        )
        assert old_acceptance["independent_fable_certification"] == (
            old_marker
        )
        assert _git(
            "rev-parse", f"{old_revision}^{{tree}}"
        ).decode().strip() == old_tree
        assert _source_content_revision_at(old_revision) == (
            old_content_revision
        )
        assert subprocess.run(
            ("git", "merge-base", "--is-ancestor", old_revision, "HEAD"),
            cwd=ROOT,
            check=False,
        ).returncode == 0
        for pointer in _evidence_pointers(old_acceptance):
            evidence_path = (
                evidence_bases[pointer["path_base"]]
                / pointer["relative_path"]
            )
            assert evidence_path.is_file()
            assert hashlib.sha256(
                evidence_path.read_bytes()
            ).hexdigest() == pointer["sha256"]
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
        == (
            "durable_circuit_integrated_fixture_only_policy_v2_"
            "live_canary_withheld"
        )
    )
    assert jaa11["objective_satisfied"] is False
    assert jaa11["claim"] == executable_slices["JAA-11"]["objective"]
    assert jaa11["depends_on"] == executable_slices["JAA-11"]["depends_on"]
    assert jaa11["provisional_fixture_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "durable_circuit_integrated_fixture_only_policy_v2_"
            "truth_finalization_pending"
        ),
        "implemented_source_git_revision": (
            "37347dcb6d5d57eb285bcae5b02c276bf5aef092"
        ),
        "implemented_source_tree": (
            "d25a012e70539ddd71b76baf4e7d29fc9ea0fd2c"
        ),
        "implemented_source_content_revision": (
            "sha256:670bf5179703e9479c952d7ff3fc370c"
            "f334876547fa85fd83269f15f0b34b75"
        ),
        "target_ats_selected": False,
        "live_canary_status": "not_collected",
        "durable_circuit_latch": True,
        "filesystem_privileged_writer_limit": (
            "surgical_partial_rewrite_undetectable_no_local_mitigation"
        ),
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
        "final_integrity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA11_12_FINAL_INTEGRITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "a04f525da6467a76500b1d17eab67e219"
                "a60803c06d10e2582040940e5f41892"
            ),
        },
        "circuit_lineage_audit": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA11_CIRCUIT_LINEAGE_AUDIT.md"
            ),
            "sha256": (
                "f678153ef80b4a98d50d036f00f21fe37"
                "d2b63899edc64f6abefcb30cda8ab0e"
            ),
        },
        "final_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_13_FINAL_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "13c0ad75c29fc5d84b918a05a172bb865"
                "720ed5d5e9cf20dfb5c8574ebb95cea"
            ),
        },
        "durable_circuit_design_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa11-durable-adapter-integration-design-raw.json"
            ),
            "sha256": (
                "3560d3ae918e015704eafe052a48e622f"
                "5942ee8f7582fd628d44c3a215319b0"
            ),
        },
        "durable_integration_phase_a_sonnet_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa11-durable-integration-phase-a-review-raw.json"
            ),
            "sha256": (
                "0bf805bdb25327c4d41e91ccd8da644f9"
                "86444eea8b2d03e081a28473371875f"
            ),
        },
        "durable_integration_phase_a_provisional_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA11_DURABLE_INTEGRATION_PHASE_A_"
                "PROVISIONAL_ACCEPTANCE.md"
            ),
            "sha256": (
                "506070f842763aadb4d512ed14e76256d"
                "97d5d46e775c0338e9d45ac303e4ea4"
            ),
        },
        "durable_integration_phase_a_fable_ruling": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa11-durable-integration-phase-a-"
                "exact-source-raw.json"
            ),
            "sha256": (
                "08bfc07f175db68c727a058eec5c512c"
                "036e304ac850913f0e4dee35ab858f60"
            ),
        },
        "durable_integration_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa11-durable-integration-phase-a-focused.log"
            ),
            "sha256": (
                "e5a68078a7f8bb28e8d95d4499140ed5"
                "39845a04843662507cf89b1d7baa5e6f"
            ),
        },
        "durable_integration_stale_truth_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa11-durable-integration-phase-a-truth-stale.log"
            ),
            "sha256": (
                "9f4fa8e9c4347efeaea57ed6341976ed1"
                "e7473ef1d63aff64badc8ff61939c6f"
            ),
        },
        "durable_integration_cross_slice_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa11-durable-integration-phase-a-cross-slice.log"
            ),
            "sha256": (
                "c79b80df7c5d70d737ff980e7a96fb9a"
                "d6c6b796d3f28ec7585edc3474994bba"
            ),
        },
        "durable_integration_ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa11-durable-integration-phase-a-ruff.log"
            ),
            "sha256": (
                "f08bdda4e29585b184a7de565669337094"
                "d783aee0e7c6c64433c32ccf809250"
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
        "final_integrity_receipt",
        "circuit_lineage_audit",
        "final_repair_focused_log",
        "durable_circuit_design_ruling",
        "durable_integration_phase_a_sonnet_review",
        "durable_integration_phase_a_provisional_receipt",
        "durable_integration_phase_a_fable_ruling",
        "durable_integration_focused_log",
        "durable_integration_stale_truth_log",
        "durable_integration_cross_slice_log",
        "durable_integration_ruff_log",
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
    assert jaa11["owns"] == [
        "career_automation/official_ats_adapter.py",
        "career_automation/durable_circuit_store.py",
    ]
    assert [test["id"] for test in jaa11["tests"]] == [
        "JAA-11-contract",
        "JAA-11-negative-controls",
        "JAA-11-durable-circuit-contract",
        "JAA-11-durable-circuit-negative-controls",
        "JAA-11-durable-integration",
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
    assert jaa12["objective_satisfied"] is False
    assert jaa12["claim"] == executable_slices["JAA-12"]["objective"]
    assert jaa12["depends_on"] == executable_slices["JAA-12"]["depends_on"]
    assert jaa12["provisional_local_export_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "bounded_local_implementation_ratified_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "37347dcb6d5d57eb285bcae5b02c276bf5aef092"
        ),
        "implemented_source_tree": (
            "d25a012e70539ddd71b76baf4e7d29fc9ea0fd2c"
        ),
        "implemented_source_content_revision": (
            "sha256:670bf5179703e9479c952d7ff3fc370c"
            "f334876547fa85fd83269f15f0b34b75"
        ),
        "upstream_dependency_satisfied": False,
        "follow_up_reference_hashes": (
            "caller_supplied_structural_references"
        ),
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
        "final_integrity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA11_12_FINAL_INTEGRITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "a04f525da6467a76500b1d17eab67e219"
                "a60803c06d10e2582040940e5f41892"
            ),
        },
        "typed_follow_up_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_TYPED_FOLLOW_UP_ACCEPTANCE.md"
            ),
            "sha256": (
                "e3d34200b31550d3b3efc1aa7bde9780"
                "f166ed70a621413d4b3f14a983a72c09"
            ),
        },
        "final_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_13_FINAL_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "13c0ad75c29fc5d84b918a05a172bb865"
                "720ed5d5e9cf20dfb5c8574ebb95cea"
            ),
        },
        "authenticity_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_16_AUTHENTICITY_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "8a39a140511d29d525f99ac958f50ee1c"
                "84e570b5e8f3439511e526b529495a5"
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
        "final_integrity_receipt",
        "typed_follow_up_receipt",
        "final_repair_focused_log",
        "authenticity_repair_focused_log",
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

    jaa13 = components["JAA-13"]
    assert (
        jaa13["increment"]
        == (
            "local_preparation_debrief_and_draft_contract_complete_"
            "dependency_refresh_and_send_withheld"
        )
    )
    assert jaa13["objective_satisfied"] is False
    assert jaa13["claim"] == executable_slices["JAA-13"]["objective"]
    assert jaa13["depends_on"] == executable_slices["JAA-13"]["depends_on"]
    assert jaa13["provisional_local_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "bounded_local_implementation_ratified_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "9bde24e294e49c98f84a16ba1f683047f8f3d1c0"
        ),
        "implemented_source_tree": (
            "b44f16daa4a5aa3857950d0bf0a577efe9b1bfad"
        ),
        "implemented_source_content_revision": (
            "sha256:5bcee41a9e30b2e288ef92d958a70fd3"
            "a28bda7fc29aea6fbeadebe98fb5520d"
        ),
        "upstream_dependency_satisfied": False,
        "submission_context_authentication": (
            "unauthenticated_structural_assertion"
        ),
        "source_refresh_authority": "withheld",
        "private_person_inference": False,
        "candidate_fact_mutation_authority": False,
        "connector_status": "not_connected",
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
        "provisional_local_contract_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA13_PROVISIONAL_LOCAL_CONTRACT_ACCEPTANCE.md"
            ),
            "sha256": (
                "fe23cf0bb50db9f13805b76b6fed07d9"
                "b779bffea2c1a3d28037376c962e26d1"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa13-post-repair-review-raw.json"
            ),
            "sha256": (
                "67facde6fbe855a24ffa191949cef22ad"
                "8d6df06e20b18ae49200400290ede60"
            ),
        },
        "positive_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa13-post-review-positive.log"
            ),
            "sha256": (
                "ba687f67e739d608d0c2920e1525f9fa"
                "9c54bbaf5dbf028d4955aed5701ab533"
            ),
        },
        "negative_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa13-post-review-negative.log"
            ),
            "sha256": (
                "21326f9afa0de598f626c77f483f8c4c"
                "c4132aaf3a74ec11b1d929e98e85bbc3"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa13-post-review-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "final_integrity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA13_FINAL_INTEGRITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "82036eb230c447517d1550808404df09ab"
                "7b74f80d090dfe0f68eca8e8e2a958"
            ),
        },
        "final_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_13_FINAL_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "13c0ad75c29fc5d84b918a05a172bb865"
                "720ed5d5e9cf20dfb5c8574ebb95cea"
            ),
        },
    }
    assert "certification" not in jaa13
    for key in (
        "deputy_authority",
        "provisional_local_contract_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_log",
        "ruff_log",
        "final_integrity_receipt",
        "final_repair_focused_log",
    ):
        pointer = jaa13["provisional_local_contract"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert jaa13["evidence"] == []
    for relative in jaa13["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-13 materialised path missing: {relative}"
        )
    for test in jaa13["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-13 declared test missing: {relative}"
            )

    jaa14 = components["JAA-14"]
    assert (
        jaa14["increment"]
        == (
            "local_outcome_feedback_contract_complete_dependency_"
            "runtime_and_promotion_withheld"
        )
    )
    assert jaa14["objective_satisfied"] is False
    assert jaa14["claim"] == executable_slices["JAA-14"]["objective"]
    assert jaa14["depends_on"] == executable_slices["JAA-14"]["depends_on"]
    assert jaa14["provisional_local_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "bounded_local_implementation_ratified_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "9bde24e294e49c98f84a16ba1f683047f8f3d1c0"
        ),
        "implemented_source_tree": (
            "b44f16daa4a5aa3857950d0bf0a577efe9b1bfad"
        ),
        "implemented_source_content_revision": (
            "sha256:5bcee41a9e30b2e288ef92d958a70fd3"
            "a28bda7fc29aea6fbeadebe98fb5520d"
        ),
        "upstream_dependency_satisfied": False,
        "runtime_learning_authority": "withheld",
        "policy_promotion_authority": "withheld",
        "gap_mutation_authority": "withheld",
        "candidate_fact_mutation_authority": False,
        "connector_status": "not_connected",
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
        "provisional_local_contract_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA14_PROVISIONAL_LOCAL_CONTRACT_ACCEPTANCE.md"
            ),
            "sha256": (
                "72d6bfe99e13040c7cd1b62314d5bc4c"
                "04815b09e5448fd1e646f294f1c77d3d"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa14-post-repair-review-raw.json"
            ),
            "sha256": (
                "97223afd4a73aa029525c964a759707a9"
                "6c4860f55f6c383cb80ceb9057d0d47"
            ),
        },
        "positive_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa14-definitive-positive.log"
            ),
            "sha256": (
                "ea1e061c27e6d298c1d2880db333e777"
                "f6b97cea348da885a5aca09ce6f354a2"
            ),
        },
        "negative_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa14-definitive-negative.log"
            ),
            "sha256": (
                "d0d5fe161f7f6a5cd079c12d188d23e7"
                "6a40df672399ddaac542c3ad8486b18b"
            ),
        },
        "upstream_cross_slice_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa14-definitive-jaa12-cross-slice.log"
            ),
            "sha256": (
                "50886ddae3b374c3062fbe873c12bb786"
                "017c5a8ded064cfcd76ee5e5e79b05e"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa14-definitive-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "final_integrity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA14_FINAL_INTEGRITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "3b4d2e1d0f30b299fb9f10e3bb6ba4b"
                "5f80f8e0ad9ef78faf9806d00b8aefd75"
            ),
        },
        "final_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_13_FINAL_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "13c0ad75c29fc5d84b918a05a172bb865"
                "720ed5d5e9cf20dfb5c8574ebb95cea"
            ),
        },
    }
    assert "certification" not in jaa14
    for key in (
        "deputy_authority",
        "provisional_local_contract_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_log",
        "upstream_cross_slice_log",
        "ruff_log",
        "final_integrity_receipt",
        "final_repair_focused_log",
    ):
        pointer = jaa14["provisional_local_contract"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert jaa14["evidence"] == []
    for relative in jaa14["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-14 materialised path missing: {relative}"
        )
    for test in jaa14["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-14 declared test missing: {relative}"
            )

    jaa15 = components["JAA-15"]
    assert (
        jaa15["increment"]
        == (
            "local_expansion_ranking_and_gate_contract_complete_"
            "dependency_runtime_and_activation_withheld"
        )
    )
    assert jaa15["objective_satisfied"] is False
    assert jaa15["claim"] == executable_slices["JAA-15"]["objective"]
    assert jaa15["depends_on"] == executable_slices["JAA-15"]["depends_on"]
    assert jaa15["provisional_local_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "bounded_local_implementation_ratified_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "37347dcb6d5d57eb285bcae5b02c276bf5aef092"
        ),
        "implemented_source_tree": (
            "d25a012e70539ddd71b76baf4e7d29fc9ea0fd2c"
        ),
        "implemented_source_content_revision": (
            "sha256:670bf5179703e9479c952d7ff3fc370c"
            "f334876547fa85fd83269f15f0b34b75"
        ),
        "upstream_dependency_satisfied": False,
        "evidence_reference_authentication": "caller_asserted_digest_only",
        "real_runtime_evidence_verified": False,
        "adapter_created_or_activated": False,
        "adapter_activation_authority": "withheld",
        "crawl_authority": "withheld",
        "connector_authority": "withheld",
        "submission_authority": "withheld",
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
        "provisional_local_contract_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA15_PROVISIONAL_LOCAL_CONTRACT_ACCEPTANCE.md"
            ),
            "sha256": (
                "9e58e34375da0bbe08b71c5acf8c87c2"
                "66430ab7d7355cad34acfe637ca11ba6"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa15-post-repair-review-raw.json"
            ),
            "sha256": (
                "6bc786e8e38cfff2241ed0224f9588b9"
                "8b2d68e56bf23815a4381cc142f2b4d1"
            ),
        },
        "positive_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa15-repair-final-positive.log"
            ),
            "sha256": (
                "fc04c4ed459b92d32a3835538d313386"
                "aceee93bf4d005bf5bb81449e34239eb"
            ),
        },
        "negative_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa15-repair-final-negative.log"
            ),
            "sha256": (
                "8e4b3699497ab4b7f7b6d603078754b8"
                "492b75fa505b7dd3e456c07790c9cd74"
            ),
        },
        "upstream_cross_slice_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa15-repair-final-jaa14-cross-slice.log"
            ),
            "sha256": (
                "825b6727fceaedd7feedac51e0d0c095b"
                "7ccde29fe9cf165ccb025cb0b6672ac"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/jaa15-repair-final-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "final_integrity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA15_16_FINAL_INTEGRITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "cd1487b30b591298dcdb25bb1ee90d1b32"
                "4fe8d98b71f5fd60d70912fd4a9a3b"
            ),
        },
        "evidence_authenticity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA15_16_EVIDENCE_AUTHENTICITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "31a89b0cdd8c0f7da30ccf8ebad7d928"
                "57e20ae5b601dcadbb9da2f31b31e864"
            ),
        },
        "authenticity_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_16_AUTHENTICITY_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "8a39a140511d29d525f99ac958f50ee1c"
                "84e570b5e8f3439511e526b529495a5"
            ),
        },
    }
    assert "certification" not in jaa15
    for key in (
        "deputy_authority",
        "provisional_local_contract_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_log",
        "upstream_cross_slice_log",
        "ruff_log",
        "final_integrity_receipt",
        "evidence_authenticity_receipt",
        "authenticity_repair_focused_log",
    ):
        pointer = jaa15["provisional_local_contract"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert jaa15["evidence"] == []
    for relative in jaa15["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-15 materialised path missing: {relative}"
        )
    for test in jaa15["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-15 declared test missing: {relative}"
            )

    jaa16 = components["JAA-16"]
    assert (
        jaa16["increment"]
        == (
            "local_operations_and_release_gate_contract_complete_"
            "dependency_runtime_distribution_and_certification_withheld"
        )
    )
    assert jaa16["objective_satisfied"] is False
    assert jaa16["claim"] == executable_slices["JAA-16"]["objective"]
    assert jaa16["depends_on"] == executable_slices["JAA-16"]["depends_on"]
    assert jaa16["provisional_local_contract"] == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "bounded_local_implementation_ratified_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "9bde24e294e49c98f84a16ba1f683047f8f3d1c0"
        ),
        "implemented_source_tree": (
            "b44f16daa4a5aa3857950d0bf0a577efe9b1bfad"
        ),
        "implemented_source_content_revision": (
            "sha256:5bcee41a9e30b2e288ef92d958a70fd3"
            "a28bda7fc29aea6fbeadebe98fb5520d"
        ),
        "upstream_dependency_satisfied": False,
        "prior_certification_and_release_evidence_authentication": (
            "unauthenticated_caller_supplied"
        ),
        "runtime_drill_evidence_verified": False,
        "distributable_artifact_verified": False,
        "release_certificate_status": "absent",
        "scheduling_authority": "withheld",
        "provider_execution_authority": "withheld",
        "deployment_authority": "withheld",
        "external_health_check_authority": "withheld",
        "report_send_authority": "withheld",
        "distribution_authority": "withheld",
        "entitlement_activation_authority": "withheld",
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
        "provisional_local_contract_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA16_PROVISIONAL_LOCAL_CONTRACT_ACCEPTANCE.md"
            ),
            "sha256": (
                "1d3eafc411d5631e53e7e10f5dbd1c3"
                "49919188ae30bfd9a8e7aa9085a15cd7b"
            ),
        },
        "sonnet_post_repair_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa16-post-repair-review-raw.json"
            ),
            "sha256": (
                "b52be842c9dabe200bd9c74c3bf533df"
                "fa3e56599797c0978acd1c3d62d8eaae"
            ),
        },
        "positive_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa16-repair-definitive-positive.log"
            ),
            "sha256": (
                "0d01c33cc7348dd2c33f14ab55819e61"
                "263f75f08ca7c4a7f899a09a19ea7e5a"
            ),
        },
        "negative_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa16-repair-definitive-negative.log"
            ),
            "sha256": (
                "b2c1e843cd81f68eba3b0e55799e8d6f"
                "6e542c3138615a7fb806e4c09a181ebd"
            ),
        },
        "acceptance_declaration_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa16-repair-definitive-acceptance-contract.log"
            ),
            "sha256": (
                "6c1f1852aded9a68ba76536c980c0a3f"
                "0382e1f1593893498a827cc83ac8f66f"
            ),
        },
        "upstream_cross_slice_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa16-repair-definitive-upstream-cross-slice.log"
            ),
            "sha256": (
                "7b928b8c7e9f5a7c5acf98504be2d901"
                "2fc5a7481c7ba7a738364ffaecb1fabe"
            ),
        },
        "ruff_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "jaa16-repair-definitive-ruff.log"
            ),
            "sha256": (
                "82b3e6a6c090a57601d22943bd23fca9"
                "218d1031dbe5a7b754092f9a156b4f18"
            ),
        },
        "final_integrity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA15_16_FINAL_INTEGRITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "cd1487b30b591298dcdb25bb1ee90d1b32"
                "4fe8d98b71f5fd60d70912fd4a9a3b"
            ),
        },
        "evidence_authenticity_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA15_16_EVIDENCE_AUTHENTICITY_ACCEPTANCE.md"
            ),
            "sha256": (
                "31a89b0cdd8c0f7da30ccf8ebad7d928"
                "57e20ae5b601dcadbb9da2f31b31e864"
            ),
        },
        "authenticity_repair_focused_log": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "SOL_JAA12_16_AUTHENTICITY_REPAIR_FOCUSED.log"
            ),
            "sha256": (
                "8a39a140511d29d525f99ac958f50ee1c"
                "84e570b5e8f3439511e526b529495a5"
            ),
        },
    }
    assert "certification" not in jaa16
    for key in (
        "deputy_authority",
        "provisional_local_contract_receipt",
        "sonnet_post_repair_review",
        "positive_log",
        "negative_log",
        "acceptance_declaration_log",
        "upstream_cross_slice_log",
        "ruff_log",
        "final_integrity_receipt",
        "evidence_authenticity_receipt",
        "authenticity_repair_focused_log",
    ):
        pointer = jaa16["provisional_local_contract"][key]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert jaa16["evidence"] == []
    release_tests = [
        test for test in jaa16["tests"]
        if test["id"] == "JAA-16-release"
    ]
    assert len(release_tests) == 1
    assert release_tests[0]["argv"] == [
        "{python}",
        "-m",
        "pytest",
        "-q",
        *release_tests[0]["files"],
    ]
    for relative in jaa16["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-16 materialised path missing: {relative}"
        )
    for test in jaa16["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-16 declared test missing: {relative}"
            )


def test_fable_ratified_local_implementation_truth_is_git_and_evidence_bound() -> None:
    components = _manifest()["components"]
    blocks = {
        "JAA-10": "bounded_local_acceptance",
        "JAA-11": "provisional_fixture_contract",
        "JAA-12": "provisional_local_export_contract",
        "JAA-13": "provisional_local_contract",
        "JAA-14": "provisional_local_contract",
        "JAA-15": "provisional_local_contract",
        "JAA-16": "provisional_local_contract",
    }
    expected_identities = {
        "JAA-10": (
            "a975d7b35cd6dd20d00cc689018b91c71bf5af63",
            "fc9cc3f33e9b326a38059d1f0191997813e791d0",
            "sha256:dcf7f436025e2c273affc352ecc8f43f"
            "841e54fe1f13310f072d170ec416bd3c",
        ),
        "JAA-11": (
            "37347dcb6d5d57eb285bcae5b02c276bf5aef092",
            "d25a012e70539ddd71b76baf4e7d29fc9ea0fd2c",
            "sha256:670bf5179703e9479c952d7ff3fc370c"
            "f334876547fa85fd83269f15f0b34b75",
        ),
        "JAA-12": (
            "37347dcb6d5d57eb285bcae5b02c276bf5aef092",
            "d25a012e70539ddd71b76baf4e7d29fc9ea0fd2c",
            "sha256:670bf5179703e9479c952d7ff3fc370c"
            "f334876547fa85fd83269f15f0b34b75",
        ),
        "JAA-13": (
            "9bde24e294e49c98f84a16ba1f683047f8f3d1c0",
            "b44f16daa4a5aa3857950d0bf0a577efe9b1bfad",
            "sha256:5bcee41a9e30b2e288ef92d958a70fd"
            "3a28bda7fc29aea6fbeadebe98fb5520d",
        ),
        "JAA-14": (
            "9bde24e294e49c98f84a16ba1f683047f8f3d1c0",
            "b44f16daa4a5aa3857950d0bf0a577efe9b1bfad",
            "sha256:5bcee41a9e30b2e288ef92d958a70fd"
            "3a28bda7fc29aea6fbeadebe98fb5520d",
        ),
        "JAA-15": (
            "37347dcb6d5d57eb285bcae5b02c276bf5aef092",
            "d25a012e70539ddd71b76baf4e7d29fc9ea0fd2c",
            "sha256:670bf5179703e9479c952d7ff3fc370c"
            "f334876547fa85fd83269f15f0b34b75",
        ),
        "JAA-16": (
            "9bde24e294e49c98f84a16ba1f683047f8f3d1c0",
            "b44f16daa4a5aa3857950d0bf0a577efe9b1bfad",
            "sha256:5bcee41a9e30b2e288ef92d958a70fd"
            "3a28bda7fc29aea6fbeadebe98fb5520d",
        ),
    }
    evidence_bases = {
        "operator_control_root": ROOT.parents[1] / ".control",
        "software_factory_root": ROOT.parents[1],
    }
    ratification_marker = (
        "bounded_local_implementation_ratified_"
        "objective_unsatisfied_2026-07-30"
    )

    for slice_id, block_name in blocks.items():
        component = components[slice_id]
        block = component[block_name]
        revision, tree, content_revision = expected_identities[slice_id]
        marker_key = (
            "independent_fable_certification"
            if slice_id == "JAA-10"
            else "independent_fable_ratification"
        )
        assert component["objective_satisfied"] is False
        expected_marker = (
            "durable_circuit_integrated_fixture_only_policy_v2_"
            "truth_finalization_pending"
            if slice_id == "JAA-11"
            else (
                "real_frozen_vacancy_bounded_local_implementation_with_"
                "canonical_contract_control_independently_accepted_"
                "objective_unsatisfied_2026-07-30"
                if slice_id == "JAA-10"
                else ratification_marker
            )
        )
        assert block[marker_key] == expected_marker
        assert "certification" not in component
        assert block["implemented_source_git_revision"] == revision
        assert block["implemented_source_tree"] == tree
        assert block["implemented_source_content_revision"] == content_revision
        assert _git("rev-parse", f"{revision}^{{tree}}").decode().strip() == tree
        assert subprocess.run(
            ("git", "merge-base", "--is-ancestor", revision, "HEAD"),
            cwd=ROOT,
            check=False,
        ).returncode == 0
        assert _source_content_revision_at(revision) == content_revision

        declared_paths = _declared_slice_paths(component)
        if slice_id == "JAA-15":
            assert len(declared_paths) == 73
            assert len(
                [path for path in declared_paths if path.startswith("scraper/")]
            ) == 67
        for relative in declared_paths:
            assert _git(
                "rev-parse", f"{revision}:{relative}"
            ) == _git("rev-parse", f"HEAD:{relative}")

        for pointer in _evidence_pointers(block):
            evidence_path = (
                evidence_bases[pointer["path_base"]]
                / pointer["relative_path"]
            )
            assert evidence_path.is_file()
            assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
                pointer["sha256"]
            )


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
