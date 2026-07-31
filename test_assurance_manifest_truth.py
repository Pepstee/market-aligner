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
        == "durable_fixture_observation_ledger_phase_a_local_only_live_withheld"
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
    assert (
        "bounded-local, fixture-scope-only, append-only, hash-chained "
        "SQLite observation ledger"
    ) in jaa10["claim"]
    jaa10_bounded = jaa10["bounded_local_acceptance"]
    assert {
        key: value
        for key, value in jaa10_bounded.items()
        if key not in {
            "dependency_independent_hard_metrics_package",
            "phase_b_fixture_measures",
            "phase_c_elapsed_cohort",
        }
    } == {
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
        "observation_ledger_phase_a": {
            "status": "ACCEPT_PHASE_A_EXACT_SOURCE",
            "scope": "bounded_local_fixture_only",
            "objective_satisfied": False,
            "implemented_source_git_revision": (
                "68f0f245b58a3ad0180f4d49ecb086d29ee0e99f"
            ),
            "implemented_source_tree": (
                "cb847d93b73ff9170543e8cf06e454c2da77d69f"
            ),
            "implemented_source_parent": (
                "91b67c83944edc4bb41cd5a0e8750c829c8d6b8b"
            ),
            "implemented_source_content_revision": (
                "sha256:940f01525d9487cf0a0bfd07bc959499"
                "9de8d0b0bd3d761d51df92b7e4cb140a"
            ),
            "prior_truth_transition": {
                "source_git_revision": (
                    "91b67c83944edc4bb41cd5a0e8750c829c8d6b8b"
                ),
                "source_tree": (
                    "d231654bfc3d86f93279feb36a42169339d45f7d"
                ),
                "source_content_revision": (
                    "sha256:34a1d329e82a542cccb06b08d7f89da"
                    "74ee8e03bc0dd5f1a0178a9df2ad72084"
                ),
                "receipt": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "FABLE_JAA10_CANONICAL_CONTRACT_CONTROL_"
                        "TRUTH_TRANSITION.md"
                    ),
                    "sha256": (
                        "475d56af52028e32a3d6af6043605dba"
                        "805f49e7c15ab62e177b22883776ffb6"
                    ),
                },
            },
            "accepted_paths": [
                {
                    "path": (
                        "career_automation/shadow_observation_ledger.py"
                    ),
                    "sha256": (
                        "45b4b5f3258344ed96c0e37318b43033"
                        "fc40d1bc58b96309a40e229ba4ca2038"
                    ),
                },
                {
                    "path": "test_jaa10_shadow_observation_ledger.py",
                    "sha256": (
                        "e90f4aa5ff17897c3f2bf8af2502cb78"
                        "ed683fc1262443ba09e38a5c5d5fa05d"
                    ),
                },
                {
                    "path": (
                        "test_jaa10_shadow_observation_ledger_"
                        "negative_controls.py"
                    ),
                    "sha256": (
                        "f194dea736861090d01bc62fa857de83e"
                        "43a9f2d42c07853e1cf325f07887099"
                    ),
                },
            ],
            "scope_claim": (
                "A bounded-local, fixture-scope-only, append-only, "
                "hash-chained SQLite observation ledger records "
                "host-generated UTC wall-clock times, captured inside the "
                "write transaction, across genuinely separate store sessions "
                "with internally generated identities; its integrity "
                "verification holds only under a non-privileged-filesystem-"
                "writer assumption and an unauthenticated local host clock; "
                "it evaluates no metrics, certifies nothing, compares no span "
                "to any separation threshold, and possesses no external-"
                "action capability. Live time-separated shadow evidence "
                "remains not collected."
            ),
            "metrics_evaluated": False,
            "live_time_separated_execution": "not_collected",
            "production_certification": "withheld",
            "withheld_reason": (
                "live_time_separated_shadow_and_metrics_not_evaluated"
            ),
            "external_action_capability": False,
            "submission_authority": "withheld",
            "release_token_authority": "withheld",
            "credential_authority": "withheld",
            "sonnet_review": {
                "session_id": (
                    "ff366d0d-0e89-4caf-b0b2-ee0aa282c53a"
                ),
                "verdict": "ACCEPT_WITH_NONBLOCKING_FINDINGS",
                "prompt_sha256": (
                    "7adc00baa8a1d581a660aeebcfee6b23d"
                    "bbe98d5d1f39d7fe2f54df79d305d0c"
                ),
                "mode": "0444",
                "artifact": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "sonnet-jaa10-observation-ledger-phase-a-"
                        "review-resume-raw.json"
                    ),
                    "sha256": (
                        "b9ae1aab74bc02947de92d1cb677d6f7"
                        "fe63bc2ec0d28054a808090db04b3da4"
                    ),
                },
                "nonblocking_findings": [
                    (
                        "No distinct record_observation clock-rollback "
                        "test."
                    ),
                    (
                        "No distinct positive observation-hash equality "
                        "assertion."
                    ),
                    (
                        "Strict same-process monotonic advance may fail "
                        "closed on a degraded coarse clock."
                    ),
                    (
                        "The initialize error path harmlessly closes SQLite "
                        "twice."
                    ),
                ],
            },
            "fable_exact_source_ruling": {
                "session_id": (
                    "7bb75a34-38de-46c3-b3c6-f1f2182454eb"
                ),
                "verdict": "ACCEPT_PHASE_A_EXACT_SOURCE",
                "prompt_sha256": (
                    "6e5e761a8bf21a37fb72664440ed045e"
                    "913ce7874934b82c1537bf17e3c68128"
                ),
                "mode": "0444",
                "artifact": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "fable-jaa10-observation-ledger-phase-a-"
                        "exact-source-raw.json"
                    ),
                    "sha256": (
                        "70f1031b1468be55044cad4325338f8c3"
                        "2a7b7b82f9d3190fab4bc92cc0d4bf3"
                    ),
                },
            },
            "deterministic_logs": {
                "new_suites": {
                    "result": "19 passed",
                    "mode": "0444",
                    "artifact": {
                        "path_base": "operator_control_root",
                        "relative_path": (
                            "jaa-single-codex-20260729/"
                            "jaa10-observation-ledger-phase-a-"
                            "new-suites-postcommit.log"
                        ),
                        "sha256": (
                            "0b49b0a9ea5d59d580a098ef32ec6978"
                            "1d1e5a98e3eea5457540f02aa5c80fe3"
                        ),
                    },
                },
                "standing_jaa10_focused": {
                    "result": "16 passed",
                    "mode": "0444",
                    "artifact": {
                        "path_base": "operator_control_root",
                        "relative_path": (
                            "jaa-single-codex-20260729/"
                            "jaa10-observation-ledger-phase-a-"
                            "focused-postcommit.log"
                        ),
                        "sha256": (
                            "db4b3425cd1671fb18dc99eec81e8e2a"
                            "d1ea99bcedbbd7b742513b220fa04b72"
                        ),
                    },
                },
                "manifest_truth": {
                    "result": "4 passed",
                    "mode": "0444",
                    "artifact": {
                        "path_base": "operator_control_root",
                        "relative_path": (
                            "jaa-single-codex-20260729/"
                            "jaa10-observation-ledger-phase-a-"
                            "manifest-postcommit.log"
                        ),
                        "sha256": (
                            "b9ba65cbca942b33073b5421795944767"
                            "4da9148ca564716ea664a3c10f673d6"
                        ),
                    },
                },
                "mutation_cohort": {
                    "result": "14 passed",
                    "mode": "0444",
                    "artifact": {
                        "path_base": "operator_control_root",
                        "relative_path": (
                            "jaa-single-codex-20260729/"
                            "jaa10-observation-ledger-phase-a-"
                            "mutation-postcommit.log"
                        ),
                        "sha256": (
                            "48f520a25e6912ce23782af64fa083471"
                            "c4a275fe3e6e2b4c261463f5056eee0"
                        ),
                    },
                },
                "standing_jaa09_real_vacancy": {
                    "result": "32 passed",
                    "mode": "0444",
                    "artifact": {
                        "path_base": "operator_control_root",
                        "relative_path": (
                            "jaa-single-codex-20260729/"
                            "jaa10-observation-ledger-phase-a-"
                            "jaa09-postcommit.log"
                        ),
                        "sha256": (
                            "7142c243dcbc3df4f408536ea643f4e51"
                            "4d3793d09266674c5ac8670f02e7b4e"
                        ),
                    },
                },
                "ruff": {
                    "result": "All checks passed!",
                    "mode": "0444",
                    "artifact": {
                        "path_base": "operator_control_root",
                        "relative_path": (
                            "jaa-single-codex-20260729/"
                            "jaa10-observation-ledger-phase-a-"
                            "ruff-postcommit.log"
                        ),
                        "sha256": (
                            "82b3e6a6c090a57601d22943bd23fca9"
                            "218d1031dbe5a7b754092f9a156b4f18"
                        ),
                    },
                },
            },
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
    hard_metrics = jaa10_bounded[
        "dependency_independent_hard_metrics_package"
    ]
    assert hard_metrics == {
        "status": "ACCEPT_BOUNDED_PACKAGE_EXACT_SOURCE",
        "scope": "dependency_independent_frozen_fixture_metrics_only",
        "implemented_source_git_revision": (
            "a8d187157dc5950136921aec1c7dfc71eefa2cd7"
        ),
        "implemented_source_parent": (
            "3514c8803faf939b6c0bb7fb5b975f3e0e765828"
        ),
        "implemented_source_tree": (
            "c053277f45127a8a546139516de3c0c61c5b16dd"
        ),
        "implemented_source_content_revision": (
            "sha256:4a84af764757149c899b604e3c931a59"
            "85077c87720f980062e588fbfb4758fe"
        ),
        "truth_transition_3514c880_ratified": True,
        "package_file_sha256": {
            "career_automation/hard_metrics_evaluation.py": (
                "9fd5728fbaa2ed4bf77cd276c095899bf"
                "2825df05781ee43ba696ef936fb8a3a"
            ),
            "career_automation/certification_candidate_compiler.py": (
                "99ff070060b816a4ae227f91ea09fd8f4"
                "c4d1442c167d9b14494ccf6c9619671"
            ),
            "test_jaa10_hard_metrics_evaluation.py": (
                "5cd052da903f71adb2b7c20638b5ed165"
                "a19454ccabf9397cfcb2362083395a2"
            ),
            "test_jaa10_hard_metrics_evaluation_negative_controls.py": (
                "07d5920a1fcebefed561e329ea40cbadd"
                "85e5035dc7b7fa9c342564e1874d7c1"
            ),
            "test_jaa10_certification_candidate_compiler.py": (
                "34385a1aceaa500d744b144c05462d103"
                "c2ea06dd619b9117cf4d966ee7ee9ff"
            ),
            (
                "test_jaa10_certification_candidate_compiler_"
                "negative_controls.py"
            ): (
                "411dccffa338c34237e5fe438fde4b236"
                "3d3bee762850e329afa85bca4890f0f"
            ),
        },
        "derived_metric_statuses": {
            "ats_parse_success_bp": "PASS",
            "confirmed_without_receipt": "UNEVALUABLE",
            "deterministic_replay_mismatch": "UNEVALUABLE",
            "duplicate_submissions": "UNEVALUABLE",
            "ineligible_submissions": "UNEVALUABLE",
            "released_employer_claims_without_citations": "UNEVALUABLE",
            "unsupported_released_claims": "UNEVALUABLE",
        },
        "ats_parse_success_basis_points": 10_000,
        "ats_parse_evidence_class": "fixture_frozen",
        "candidate_status": "CERTIFICATION_WITHHELD",
        "candidate_withheld_reasons": [
            "live_evidence_absent",
            "signed_time_absent",
            "metrics_incomplete",
        ],
        "sonnet_review": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-hard-metrics-package-review-raw.json"
            ),
            "sha256": (
                "d91b7242d69688b744d6cd8a232d98ca"
                "968158ea8d52cb547174c6286e1dd58c"
            ),
            "session_id": "3452a591-c0ac-4ff5-aed6-ee60c9bc8915",
            "disposition": (
                "IMPLEMENTATION_REVIEW_DECISION: ACCEPT_WITH_FINDINGS"
            ),
        },
        "implementation_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "JAA10_HARD_METRICS_PACKAGE_IMPLEMENTATION_RECEIPT.md"
            ),
            "sha256": (
                "7e401ab88dad8a24c6d001688bd8b5816"
                "4eb0e73d5bd9a29b08a20778b176f56"
            ),
        },
        "acceptance_authority": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-hard-metrics-package-"
                "exact-source-gate-raw.json"
            ),
            "sha256": (
                "0971d3a7f42d0931db5f03afbbe3188e"
                "fae4eef2277aceeb02a5c9ba1ee57b44"
            ),
        },
        "independent_fable_certification": False,
        "objective_satisfied": False,
        "certifies_slice": False,
        "live_metrics_evaluated": False,
        "production_certification": "withheld",
        "live_time_separated_execution": "not_collected",
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }
    for relative, expected_sha256 in hard_metrics[
        "package_file_sha256"
    ].items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == (
            expected_sha256
        )
    assert _git(
        "rev-parse",
        f"{hard_metrics['implemented_source_git_revision']}^",
    ).decode().strip() == hard_metrics["implemented_source_parent"]
    assert _git(
        "rev-parse",
        f"{hard_metrics['implemented_source_git_revision']}^{{tree}}",
    ).decode().strip() == hard_metrics["implemented_source_tree"]
    assert _source_content_revision_at(
        hard_metrics["implemented_source_git_revision"]
    ) == hard_metrics["implemented_source_content_revision"]
    hard_metrics_gate_hash_index = {
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-hard-metrics-package-exact-source-gate-raw.json"
        ): "0971d3a7f42d0931db5f03afbbe3188efae4eef2277aceeb02a5c9ba1ee57b44"
    }
    assert hard_metrics_gate_hash_index == {
        hard_metrics["acceptance_authority"]["relative_path"]: (
            hard_metrics["acceptance_authority"]["sha256"]
        )
    }
    for relative_path, expected_sha256 in (
        hard_metrics_gate_hash_index.items()
    ):
        evidence_path = ROOT.parents[1] / ".control" / relative_path
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            expected_sha256
        )
        assert evidence_path.stat().st_mode & 0o777 == 0o444
    phase_b = jaa10_bounded["phase_b_fixture_measures"]
    assert set(phase_b) == {
        "status",
        "scope",
        "implemented_source_git_revision",
        "implemented_source_tree",
        "implemented_source_parent",
        "implemented_source_branch",
        "implemented_source_content_revision",
        "report_schema_version",
        "report_identity_domain",
        "accepted_paths",
        "design_authority",
        "sonnet_review",
        "fable_exact_source_ruling",
        "phase_a_ancestry",
        "deterministic_logs",
        "strongest_claim",
        "objective_satisfied",
        "metrics_evaluated",
        "hard_quality_targets",
        "live_time_separated_execution",
        "production_certification",
        "withheld_reason",
        "certifies_slice",
        "external_action_capability",
        "assessment",
        "submission_authority",
        "release_token_authority",
        "credential_authority",
    }
    phase_b_revision = "2d94075c3abe4feddd50a6a7546e7af2c8cfa18a"
    assert phase_b["status"] == "ACCEPT_PHASE_B_EXACT_SOURCE"
    assert phase_b["scope"] == "bounded_local_fixture_only"
    assert phase_b["implemented_source_git_revision"] == phase_b_revision
    assert phase_b["implemented_source_tree"] == (
        "8a582e126ba3299a722c21a8bf20a1af462e2e5e"
    )
    assert phase_b["implemented_source_parent"] == (
        "3ee8584458705ac0d8f859d9e832ad9ad8aa97c7"
    )
    assert phase_b["implemented_source_branch"] == (
        "codex/jaa-native-completion-20260725"
    )
    assert phase_b["implemented_source_content_revision"] == (
        "sha256:1d8374bcb68ea66008e5acaa9287917d"
        "4e85203f4ebfff5c722b9d2de21e3c1c"
    )
    assert phase_b["report_schema_version"] == (
        "jaa10.shadow-fixture-measures-report.v1"
    )
    assert phase_b["report_identity_domain"] == (
        "jaa10-shadow-fixture-measures-report-v1\0"
    )
    assert _git(
        "rev-parse", f"{phase_b_revision}^{{tree}}"
    ).decode().strip() == phase_b["implemented_source_tree"]
    assert _git(
        "rev-parse", f"{phase_b_revision}^"
    ).decode().strip() == phase_b["implemented_source_parent"]
    assert _source_content_revision_at(phase_b_revision) == (
        phase_b["implemented_source_content_revision"]
    )
    assert subprocess.run(
        ("git", "merge-base", "--is-ancestor", phase_b_revision, "HEAD"),
        cwd=ROOT,
        check=False,
    ).returncode == 0
    assert phase_b["accepted_paths"] == [
        {
            "path": "career_automation/shadow_fixture_measures.py",
            "sha256": (
                "6fcc7c329fbff895e4b0b9830ce4aed14"
                "f601ec2be683cb601a1693aad620297"
            ),
        },
        {
            "path": "test_jaa10_shadow_fixture_measures.py",
            "sha256": (
                "a4f05f29ec801ff84caf77f82560b1832"
                "18c4f65568b016f2d910b4d3f030abe"
            ),
        },
        {
            "path": (
                "test_jaa10_shadow_fixture_measures_negative_controls.py"
            ),
            "sha256": (
                "fbbc561f48944a6ca7eea636ef1138b47"
                "0bb21d6fa620c42904f7c520993c779"
            ),
        },
    ]
    for accepted_path in phase_b["accepted_paths"]:
        relative = accepted_path["path"]
        candidate_payload = _git("show", f"{phase_b_revision}:{relative}")
        assert hashlib.sha256(candidate_payload).hexdigest() == (
            accepted_path["sha256"]
        )
        assert _git(
            "rev-parse", f"{phase_b_revision}:{relative}"
        ) == _git("rev-parse", f"HEAD:{relative}")
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == (
            accepted_path["sha256"]
        )
    assert phase_b["design_authority"] == {
        "session_id": "49045bd7-73d2-46db-92b8-65dd745bd7d5",
        "disposition": "AUTHORIZE_REVISED_PHASE_B_DESIGN",
        "mode": "0444",
        "artifact": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-phase-b-metrics-design-gate-raw.json"
            ),
            "sha256": (
                "c6364e1193ec97b412f5c75b64edc688"
                "4cc1b1bbd1e5ebf31bdbb7e7939bcc34"
            ),
        },
    }
    assert phase_b["sonnet_review"] == {
        "session_id": "16220c7b-4ced-40ce-a06c-4bab0a575b1d",
        "verdict": "ACCEPT_WITH_NONBLOCKING_FINDINGS",
        "prompt_sha256": (
            "006bda9b15c12b7f873ed4dbca22cb8a"
            "72a9701d95e75fcaf9c05659b29f37e9"
        ),
        "mode": "0444",
        "artifact": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-phase-b-fixture-measures-review-raw.json"
            ),
            "sha256": (
                "4b477b618a634927fe0c26296464113237"
                "cb00d257b26b54e38f28af674d9c79"
            ),
        },
        "nonblocking_findings": [
            (
                "Receipt tuple reordering is structurally rejected by exact "
                "sequence checks but lacks a dedicated test."
            ),
            (
                "Offline verification does not embed the genesis receipt; "
                "current verification binds ledger identity."
            ),
            (
                "Action keys seed from the first typed observation while "
                "every typed observation enforces the complete action set."
            ),
        ],
        "resolved_source_revision_note": (
            "The documented tracked_source_revision."
            "source_content_revision command reproduces the accepted "
            "source-content revision exactly."
        ),
    }
    assert phase_b["fable_exact_source_ruling"] == {
        "session_id": "994b3ffc-efa1-4481-86a3-f31da794443c",
        "disposition": "ACCEPT_PHASE_B_EXACT_SOURCE",
        "prompt_sha256": (
            "1d931cbda75d243568e5a7ae58e7c53b"
            "be05c90b4f5c96cf7b77c54881281c62"
        ),
        "mode": "0444",
        "artifact": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-phase-b-fixture-measures-"
                "exact-source-raw.json"
            ),
            "sha256": (
                "2ee181f5cd6fd5c8ac2465816b5c41259"
                "e86b9cb3653bd1466a09e0d381954d3"
            ),
        },
    }
    assert phase_b["phase_a_ancestry"] == {
        "accepted_implementation_revision": (
            "68f0f245b58a3ad0180f4d49ecb086d29ee0e99f"
        ),
        "round_116_truth_transition_receipt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "FABLE_JAA10_OBSERVATION_LEDGER_PHASE_A_"
                "TRUTH_TRANSITION.md"
            ),
            "sha256": (
                "226d6cf7724bc869e089a51c1abd86726"
                "b3d9b170379b4f620bcc04f68289799"
            ),
        },
    }
    assert subprocess.run(
        (
            "git",
            "merge-base",
            "--is-ancestor",
            phase_b["phase_a_ancestry"][
                "accepted_implementation_revision"
            ],
            phase_b_revision,
        ),
        cwd=ROOT,
        check=False,
    ).returncode == 0
    expected_phase_b_evidence = {
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-b-metrics-design-gate-raw.json"
        ): "c6364e1193ec97b412f5c75b64edc6884cc1b1bbd1e5ebf31bdbb7e7939bcc34",
        (
            "jaa-single-codex-20260729/"
            "sonnet-jaa10-phase-b-fixture-measures-review-raw.json"
        ): "4b477b618a634927fe0c26296464113237cb00d257b26b54e38f28af674d9c79",
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-b-fixture-measures-exact-source-raw.json"
        ): "2ee181f5cd6fd5c8ac2465816b5c41259e86b9cb3653bd1466a09e0d381954d3",
        (
            "jaa-single-codex-20260729/"
            "FABLE_JAA10_OBSERVATION_LEDGER_PHASE_A_TRUTH_TRANSITION.md"
        ): "226d6cf7724bc869e089a51c1abd86726b3d9b170379b4f620bcc04f68289799",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-new-suites-postcommit.log"
        ): "9342c4cebc47721fbda71cec810ec6aecb97e4a8c9a575040a1ddff0369563b6",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-ledger-postcommit.log"
        ): "e2ebf47a50a184103eefd68156713da769df5ca7f875a79cb44f209944154658",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-manifest-postcommit.log"
        ): "4b0e8fe4a5cee60d17a9a5bbc3675786a42a24bac07ad58b0f2be92bb4e73875",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-focused-postcommit.log"
        ): "2fa3b4ec16d02b794d23f40cdf74cf3a4cd35a342a49e5d8a3410c0fdd33d0f8",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-mutation-postcommit.log"
        ): "8116eb849876d9b4f1b3babf137d2a47ee89ef6a04ef30149a3dfc536b9a6c4f",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-jaa09-postcommit.log"
        ): "a15b54024a8da850dd701a09fd8a8155fc440ec685a324e50811a8f49784d212",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-ruff-postcommit.log"
        ): "82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-allowlist-postcommit.log"
        ): "df11aa6e5a6b63c6e23cb614bf0f4adfd4081d1e8195606226db15ddc1fcb0d2",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-compileall-postcommit.log"
        ): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-diff-check-postcommit.log"
        ): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-b-fixture-measures-status-postcommit.log"
        ): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    phase_b_evidence = {
        pointer["relative_path"]: pointer["sha256"]
        for pointer in _evidence_pointers(phase_b)
    }
    assert phase_b_evidence == expected_phase_b_evidence
    for relative_path, expected_sha256 in expected_phase_b_evidence.items():
        evidence_path = evidence_bases["operator_control_root"] / relative_path
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            expected_sha256
        )
    assert set(phase_b["deterministic_logs"]) == {
        "new_suites",
        "standing_ledger",
        "manifest_truth",
        "standing_jaa10_focused",
        "mutation_cohort",
        "standing_jaa09_real_vacancy",
        "ruff",
        "allowlist",
        "compileall",
        "diff_check",
        "clean_status",
    }
    assert {
        key: record["result"]
        for key, record in phase_b["deterministic_logs"].items()
    } == {
        "new_suites": "41 passed",
        "standing_ledger": "19 passed",
        "manifest_truth": "4 passed",
        "standing_jaa10_focused": "16 passed",
        "mutation_cohort": "14 passed",
        "standing_jaa09_real_vacancy": "32 passed",
        "ruff": "All checks passed!",
        "allowlist": "exact three add-only paths",
        "compileall": "empty_success",
        "diff_check": "empty_success",
        "clean_status": "empty_success",
    }
    assert all(
        record["mode"] == "0444"
        for record in phase_b["deterministic_logs"].values()
    )
    assert phase_b["strongest_claim"] == (
        "descriptive fixture measures, recomputed from hash-bound typed "
        "observations bound one-for-one to a verified append-only fixture "
        "ledger snapshot, under an unauthenticated local clock and a "
        "non-privileged-filesystem-writer assumption."
    )
    assert phase_b["objective_satisfied"] is False
    assert phase_b["metrics_evaluated"] is False
    assert phase_b["hard_quality_targets"] == {
        "ats_parse_success_bp": {
            "target": 10_000,
            "status": "not_evaluable_from_fixture_ledger",
        },
        "confirmed_without_receipt": {
            "target": 0,
            "status": "not_evaluable_from_fixture_ledger",
        },
        "deterministic_replay_mismatch": {
            "target": 0,
            "status": "not_evaluable_from_fixture_ledger",
        },
        "duplicate_submissions": {
            "target": 0,
            "status": "not_evaluable_from_fixture_ledger",
        },
        "ineligible_submissions": {
            "target": 0,
            "status": "not_evaluable_from_fixture_ledger",
        },
        "released_employer_claims_without_citations": {
            "target": 0,
            "status": "not_evaluable_from_fixture_ledger",
        },
        "unsupported_released_claims": {
            "target": 0,
            "status": "not_evaluable_from_fixture_ledger",
        },
    }
    assert phase_b["live_time_separated_execution"] == "not_collected"
    assert phase_b["production_certification"] == "withheld"
    assert phase_b["withheld_reason"] == (
        "live_time_separated_shadow_and_metrics_not_evaluated"
    )
    assert phase_b["certifies_slice"] is False
    assert phase_b["external_action_capability"] is False
    assert phase_b["assessment"] == (
        "withheld_pending_fable_live_execution_gate"
    )
    for authority in (
        "submission_authority",
        "release_token_authority",
        "credential_authority",
    ):
        assert phase_b[authority] == "withheld"
    phase_c = jaa10_bounded["phase_c_elapsed_cohort"]
    assert set(phase_c) == {
        "status",
        "scope",
        "implemented_source_git_revision",
        "implemented_source_tree",
        "implemented_source_parent",
        "implemented_source_branch",
        "implemented_source_content_revision",
        "cohort_schema_version",
        "evidence_class",
        "maximum_claim",
        "cohort_status",
        "open_runtime_evidence",
        "accepted_paths",
        "design_authority",
        "sonnet_review",
        "fable_exact_source_ruling",
        "deterministic_logs",
        "strongest_claim",
        "contamination_policy",
        "calendar_time_authentication",
        "external_time_attestation",
        "filesystem_privileged_writer_limit",
        "kernel_time_witness_limit",
        "objective_satisfied",
        "metrics_evaluated",
        "hard_quality_targets",
        "live_time_separated_execution",
        "production_certification",
        "withheld_reason",
        "certifies_slice",
        "external_action_capability",
        "real_applications_submitted",
        "assessment",
        "submission_authority",
        "release_token_authority",
        "credential_authority",
        "browser_network_authority",
    }
    phase_c_revision = "f0254ac0a696c20368f59d3eab04c09d16655550"
    assert phase_c["status"] == (
        "ACCEPT_PHASE_C_BOUNDED_LOCAL_EXACT_SOURCE"
    )
    assert phase_c["scope"] == "bounded_local_fixture_only"
    assert phase_c["implemented_source_git_revision"] == phase_c_revision
    assert phase_c["implemented_source_tree"] == (
        "3d1721b292f137817a038a32596ec72089b0b519"
    )
    assert phase_c["implemented_source_parent"] == (
        "52e853b920ce0af235117afa1b004243757e331f"
    )
    assert phase_c["implemented_source_branch"] == (
        "codex/jaa-native-completion-20260725"
    )
    assert phase_c["implemented_source_content_revision"] == (
        "sha256:9fba6283d836621569c42157e605b6bf"
        "ed18280ded845e1e3a9daed89a875cfc"
    )
    assert phase_c["cohort_schema_version"] == (
        "jaa10.shadow-elapsed-cohort.v1"
    )
    assert phase_c["evidence_class"] == (
        "loopback_fixture_browser_elapsed"
    )
    assert phase_c["maximum_claim"] == (
        "loopback_fixture_elapsed_interval_same_boot_local_only"
    )
    assert phase_c["cohort_status"] == (
        "open_not_closed_not_collected"
    )
    open_runtime = phase_c["open_runtime_evidence"]
    assert set(open_runtime) == {
        "cohort_id",
        "open_receipt_sha256",
        "observation_id",
        "observation_sha256",
        "ledger_instance_id",
        "genesis_receipt_sha256",
        "chain_head_receipt_sha256",
        "ledger_receipt_count",
        "fixture_measures_report_id",
        "first_witness",
        "ledger_sha256_at_open",
        "artifact_sha256_at_open",
        "browser_work",
        "public_network_requests",
        "network_isolation_witness_limit",
        "cohort_close_attempted_at_record",
        "current_source_eligible",
        "permanently_non_closeable_for_current_source",
        "ineligibility_reason",
        "ineligible_since_head",
        "ineligibility_authority",
        "incomplete_attempt",
        "immutable_evidence",
    }
    assert open_runtime["cohort_id"] == (
        "6f899b49467ab28e5c19af6b5aba9dd2"
        "1274d374d1d05dbbd457fcf130987693"
    )
    assert open_runtime["open_receipt_sha256"] == (
        "22f26d138e758a83f78a808f8ecfef9d"
        "f20caa963d0eefb7b79f7e80c3ca9e1d"
    )
    assert open_runtime["observation_id"] == (
        "jaa10-phase-c-open-9246458"
    )
    assert open_runtime["observation_sha256"] == (
        "480357d4fbaaaa7bf47353cb703997751"
        "a65c167d3470bb1b11de9a26f443ae4"
    )
    assert open_runtime["ledger_instance_id"] == (
        "ff1f71f999651ccdd819e42ef1e5afae"
        "be19aceac19b9dc91eee43fa0368bf4d"
    )
    assert open_runtime["genesis_receipt_sha256"] == (
        "b88249ea97ebdf0f3a23b9ca60ff5232"
        "fb73fa1fd8f711412ff6b726940fba31"
    )
    assert open_runtime["chain_head_receipt_sha256"] == (
        "66d3c6872938c74926d648d8c53f54ef"
        "22071bff2ba059fd5b5aa32a213379fe"
    )
    assert open_runtime["ledger_receipt_count"] == 3
    assert open_runtime["current_source_eligible"] is False
    assert (
        open_runtime["permanently_non_closeable_for_current_source"] is True
    )
    assert open_runtime["ineligibility_reason"] == (
        "product_execution_files_changed_since_open"
    )
    assert open_runtime["ineligible_since_head"] == (
        "3d239d40ac7a74f6f390e231d967ed85dca4e4d7"
    )
    assert open_runtime["ineligibility_authority"] == {
        "path_base": "operator_control_root",
        "relative_path": (
            "jaa-single-codex-20260729/"
            "fable-jaa10-live-shadow-hard-metrics-design-v2-gate-raw.json"
        ),
        "sha256": (
            "342edb0306f8622293d6778da7b87139"
            "3f1b7a66dfd3698ff31c2940eb380f62"
        ),
    }
    assert open_runtime["fixture_measures_report_id"] == (
        "9796e3839fdbe8bbaba63e2c3b6014c9"
        "0e31937a818aea8ab5482ee2f3c902eb"
    )
    assert open_runtime["first_witness"] == {
        "boot_id_sha256": (
            "9d6ad2cc5bc6547443e97a1d5667e73f"
            "ef732b1b4af080077366798b93903c77"
        ),
        "clock_boottime_ns": 642_873_679_497_750,
        "monotonic_ns": 642_873_679_498_909,
        "process_token": (
            "4d76f06f21737909b9c6dba0226f2df"
            "c4bd1c9a08f24b19535ee47504cb0ff81"
        ),
        "recorded_wall_clock": "2026-07-30T12:08:49.810648+00:00",
        "recorded_wall_clock_status": "informational",
    }
    assert open_runtime["ledger_sha256_at_open"] == (
        "0a08dfcb418e389d57be38fdb764b8c37"
        "e68ef8ee081599545b6622ec2a10388"
    )
    assert open_runtime["artifact_sha256_at_open"] == {
        "metadata.json": {
            "sha256": (
                "708eec015ca5898055157204a48529259"
                "3d793400a3d2747f790e5d0e1b917de"
            ),
            "status": "as_of_open",
        },
        "observation.json": {
            "sha256": (
                "c484ad6dae19942984120800a95a241c6"
                "f75f2f85a80f89a86bfe6aebcc80df6"
            ),
            "status": "as_of_open",
        },
        "ledger-identity.json": {
            "sha256": (
                "5e4c740f2eb9293c908b3bd00b38ee68"
                "b2d6b4499c6e2464ac971a2cfbbc6cf8"
            ),
            "status": "as_of_open",
        },
        "ledger-receipt.json": {
            "sha256": (
                "472d93af860a76c7e272fdeab482dd416"
                "e4c9b75fd546ead3fb4c5c5bf51507b"
            ),
            "status": "as_of_open",
        },
        "fixture-measures-report.json": {
            "sha256": (
                "c4dacea7eb7b6c56dda3154b9865a16f"
                "47286c827609c45446838b6de8f3d95f"
            ),
            "status": "as_of_open",
        },
        "open-receipt.json": {
            "sha256": (
                "89eddda0b97061e45208bc1e5efdf0bd"
                "1b7f991539f73735b6f95777e7343ab4"
            ),
            "status": "as_of_open",
        },
        "shadow-observations.sqlite3": {
            "sha256": (
                "0a08dfcb418e389d57be38fdb764b8c37"
                "e68ef8ee081599545b6622ec2a10388"
            ),
            "status": "as_of_open",
        },
    }
    assert open_runtime["browser_work"] == {
        "file_count": 84,
        "total_bytes": 4_948_470,
        "inventory_sha256": (
            "150f80bf8190a6521cb2e494daa76cf7"
            "85de7bff1c3b161ff7289c53d1ec357a"
        ),
        "inventory_domain": (
            "jaa10-phase-c-browser-work-inventory-v1"
        ),
        "inventory_algorithm": (
            "root is the active runtime root's `browser-work` directory; "
            "files are every recursive regular file sorted by relative "
            "POSIX path; initialize SHA-256 with bytes "
            '`b"jaa10-phase-c-browser-work-inventory-v1\\0"`; for each '
            "file update with: 8-byte big-endian relative-path byte "
            "length; relative POSIX path bytes; 4-byte big-endian "
            "`(st_mode & 0o777)`; 8-byte big-endian content length; raw "
            "32-byte SHA-256 digest of the content."
        ),
    }
    assert open_runtime["public_network_requests"] == 0
    assert open_runtime["network_isolation_witness_limit"] == (
        "cooperative_inprocess_loopback_controls_and_artifact_"
        "corroboration_no_os_level_traffic_audit"
    )
    assert open_runtime["cohort_close_attempted_at_record"] is False
    assert open_runtime["incomplete_attempt"] == {
        "relative_path": (
            "jaa10-phase-c-open-cohort-9246458-attempt1-incomplete"
        ),
        "ledger_sha256": (
            "9adeef327e42af2a1fa61847638ff8afe"
            "99c05fe32bfb13bd332cc1b8b4ac819"
        ),
        "disposition": "preserved_disclosed_not_active",
    }
    assert open_runtime["immutable_evidence"] == {
        "open_receipt": {
            "mode": "0444",
            "artifact": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "JAA10_PHASE_C_OPEN_COHORT_RECEIPT.md"
                ),
                "sha256": (
                    "b3d969a5d27658d45a58c62c9349bdeb"
                    "01c2860434a8c4fcd874f855fcea0f51"
                ),
            },
        },
        "durable_reconstruction_log": {
            "mode": "0444",
            "artifact": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "jaa10-phase-c-open-cohort-durable-reconstruction.log"
                ),
                "sha256": (
                    "48fae5f0eff4d15fe1508c4424d75a966"
                    "45d1f2c785ba5dd785233be59f201fe"
                ),
            },
        },
        "sonnet_review": {
            "session_id": "da3d680c-d3c2-4047-af9e-2d52228a4700",
            "disposition": "ACCEPT_WITH_NONBLOCKING_FINDINGS",
            "mode": "0444",
            "prompt": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "sonnet-jaa10-phase-c-open-cohort-review-prompt.txt"
                ),
                "sha256": (
                    "3db5177dba27a93c8e914ff475f2f5829"
                    "61b6e5265722fc7ffca237d753130c0"
                ),
            },
            "artifact": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "sonnet-jaa10-phase-c-open-cohort-review-raw.json"
                ),
                "sha256": (
                    "6713b84aa1e026815af5df9a5374e032"
                    "1ba1f497b6e35aa902af9f4b92189260"
                ),
            },
        },
        "fable_runtime_ruling": {
            "session_id": "09321b59-aec5-4a44-bcd5-5eccdc18bd5e",
            "disposition": "ACCEPT_OPEN_COHORT_EXACT_RUNTIME_EVIDENCE",
            "mode": "0444",
            "prompt": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "fable-jaa10-phase-c-open-cohort-runtime-gate-"
                    "prompt.txt"
                ),
                "sha256": (
                    "302fe31268e9a994e34b55b129c462b6"
                    "9d2ab302223549909aeb687f61fc2a31"
                ),
            },
            "artifact": {
                "path_base": "operator_control_root",
                "relative_path": (
                    "jaa-single-codex-20260729/"
                    "fable-jaa10-phase-c-open-cohort-runtime-gate-"
                    "raw.json"
                ),
                "sha256": (
                    "e182f5517ee1f5b4d4845e020b593e5e"
                    "1c02666e33dec8cebf218a2d74ebabb5"
                ),
            },
        },
    }
    assert _git(
        "rev-parse", f"{phase_c_revision}^{{tree}}"
    ).decode().strip() == phase_c["implemented_source_tree"]
    assert _git(
        "rev-parse", f"{phase_c_revision}^"
    ).decode().strip() == phase_c["implemented_source_parent"]
    assert _source_content_revision_at(phase_c_revision) == (
        phase_c["implemented_source_content_revision"]
    )
    assert subprocess.run(
        ("git", "merge-base", "--is-ancestor", phase_c_revision, "HEAD"),
        cwd=ROOT,
        check=False,
    ).returncode == 0
    assert phase_c["accepted_paths"] == [
        {
            "path": "career_automation/shadow_elapsed_cohort.py",
            "sha256": (
                "d658cb48c71780f273c47ee7d5db2854a"
                "f242a7d41664fa12f7a60d1eed97e49"
            ),
        },
        {
            "path": "test_jaa10_shadow_elapsed_cohort.py",
            "sha256": (
                "24e3044bece7ebe8cda26faa3abc089c8e"
                "3b8907f4d591ae650da3cf6e5ddda7"
            ),
        },
        {
            "path": (
                "test_jaa10_shadow_elapsed_cohort_negative_controls.py"
            ),
            "sha256": (
                "88aa80d3118f50d51e8d0150b573d33e"
                "25881dd8207f9c3d24a1a801eed84c14"
            ),
        },
    ]
    for accepted_path in phase_c["accepted_paths"]:
        relative = accepted_path["path"]
        candidate_payload = _git("show", f"{phase_c_revision}:{relative}")
        assert hashlib.sha256(candidate_payload).hexdigest() == (
            accepted_path["sha256"]
        )
        assert _git(
            "rev-parse", f"{phase_c_revision}:{relative}"
        ) == _git("rev-parse", f"HEAD:{relative}")
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == (
            accepted_path["sha256"]
        )
    assert phase_c["design_authority"] == {
        "session_id": "3c34bcf8-b801-4eb0-ae7c-c3460e060ff0",
        "disposition": (
            "DEPENDENCY_BLOCKED_WITH_AUTHORIZED_PREPARATION"
        ),
        "mode": "0444",
        "artifact": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-phase-c-live-shadow-design-gate-raw.json"
            ),
            "sha256": (
                "733a756a121ce5756e21b86ff06b3e6d7"
                "3fa4f463e52071092ff30f1d5b3a77f"
            ),
        },
    }
    assert phase_c["sonnet_review"] == {
        "session_id": "6ef1b1e2-376e-473a-8565-2afec2c9df19",
        "final_event_uuid": "f14d55a9-9195-4b54-a846-d98e4f574576",
        "verdict": "ACCEPT_WITH_NONBLOCKING_FINDINGS",
        "mode": "0444",
        "prompt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-phase-c-elapsed-cohort-review-prompt.txt"
            ),
            "sha256": (
                "393d2848a1afbde49aae4fcd6eef10b1b"
                "e9260719dd8f6ffe7b43f3b3e61b90c"
            ),
        },
        "artifact": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "sonnet-jaa10-phase-c-elapsed-cohort-review-raw.jsonl"
            ),
            "sha256": (
                "dee086ab1aee4f9a412747738500c39712"
                "f4de8818893bb7f70f2e0da686838e"
            ),
        },
        "nonblocking_findings": [
            {
                "finding": (
                    "Module-private validation helpers can inject witness "
                    "values and produce structurally identical bounded "
                    "receipts."
                ),
                "adjudication": (
                    "nonblocking_design_authorized_validation_layer_"
                    "public_entry_points_capture_kernel_witnesses"
                ),
            },
            {
                "finding": (
                    "Active-process double-close prevention does not "
                    "persist across process restart."
                ),
                "adjudication": (
                    "nonblocking_redundant_bounded_receipt_cannot_elevate_"
                    "withheld_claims"
                ),
            },
        ],
    }
    assert phase_c["fable_exact_source_ruling"] == {
        "session_id": "4855a5ea-4076-470a-a21a-54fc45827442",
        "disposition": (
            "ACCEPT_PHASE_C_BOUNDED_LOCAL_EXACT_SOURCE"
        ),
        "mode": "0444",
        "prompt": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-phase-c-elapsed-cohort-"
                "exact-source-prompt.txt"
            ),
            "sha256": (
                "269bab941961f071cd8022e4b3591803d"
                "6d72f23f246e2adcad2f92178b2ce7f"
            ),
        },
        "artifact": {
            "path_base": "operator_control_root",
            "relative_path": (
                "jaa-single-codex-20260729/"
                "fable-jaa10-phase-c-elapsed-cohort-"
                "exact-source-raw.json"
            ),
            "sha256": (
                "02ea7c00e47f8950eb15de6f00a7e87d9"
                "2d86f846ac7f06af5ba04a91103441a"
            ),
        },
    }
    expected_phase_c_evidence = {
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-c-live-shadow-design-gate-raw.json"
        ): "733a756a121ce5756e21b86ff06b3e6d73fa4f463e52071092ff30f1d5b3a77f",
        (
            "jaa-single-codex-20260729/"
            "sonnet-jaa10-phase-c-elapsed-cohort-review-prompt.txt"
        ): "393d2848a1afbde49aae4fcd6eef10b1be9260719dd8f6ffe7b43f3b3e61b90c",
        (
            "jaa-single-codex-20260729/"
            "sonnet-jaa10-phase-c-elapsed-cohort-review-raw.jsonl"
        ): "dee086ab1aee4f9a412747738500c39712f4de8818893bb7f70f2e0da686838e",
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-c-elapsed-cohort-exact-source-prompt.txt"
        ): "269bab941961f071cd8022e4b3591803d6d72f23f246e2adcad2f92178b2ce7f",
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-c-elapsed-cohort-exact-source-raw.json"
        ): "02ea7c00e47f8950eb15de6f00a7e87d92d86f846ac7f06af5ba04a91103441a",
        (
            "jaa-single-codex-20260729/"
            "JAA10_PHASE_C_OPEN_COHORT_RECEIPT.md"
        ): "b3d969a5d27658d45a58c62c9349bdeb01c2860434a8c4fcd874f855fcea0f51",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-open-cohort-durable-reconstruction.log"
        ): "48fae5f0eff4d15fe1508c4424d75a96645d1f2c785ba5dd785233be59f201fe",
        (
            "jaa-single-codex-20260729/"
            "sonnet-jaa10-phase-c-open-cohort-review-prompt.txt"
        ): "3db5177dba27a93c8e914ff475f2f582961b6e5265722fc7ffca237d753130c0",
        (
            "jaa-single-codex-20260729/"
            "sonnet-jaa10-phase-c-open-cohort-review-raw.json"
        ): "6713b84aa1e026815af5df9a5374e0321ba1f497b6e35aa902af9f4b92189260",
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-c-open-cohort-runtime-gate-prompt.txt"
        ): "302fe31268e9a994e34b55b129c462b69d2ab302223549909aeb687f61fc2a31",
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-phase-c-open-cohort-runtime-gate-raw.json"
        ): "e182f5517ee1f5b4d4845e020b593e5e1c02666e33dec8cebf218a2d74ebabb5",
        (
            "jaa-single-codex-20260729/"
            "fable-jaa10-live-shadow-hard-metrics-design-v2-gate-raw.json"
        ): "342edb0306f8622293d6778da7b871393f1b7a66dfd3698ff31c2940eb380f62",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-new-suites-postcommit.log"
        ): "29680a96da0fb4e585730694fbf09e8386a72b7ebebe44b0f1c0fa802f639aa2",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-phase-b-postcommit.log"
        ): "639990e9e0b84b7a3053feb3ff212cbd4bc3ae955ca8d87939ee016d0e0a70b4",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-phase-a-postcommit.log"
        ): "82307027379c2be9addf6c8bb7403e8d4de6be9c975b5ba1f9c35d82dcd39b55",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-manifest-postcommit.log"
        ): "9d5adbac0eaa86d9927f93032cbb9d4d0343464ad8360b04cd68949a72c00c50",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-focused-postcommit.log"
        ): "e2c3bdd23df73a465035ab586b78271640dda35335a16a18f7860b7786c2f15c",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-mutation-postcommit.log"
        ): "ede8c4a839ce2b65d0c2de85e95fd9135afccce8a53c2bb04e5c3c196decd157",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-jaa09-postcommit.log"
        ): "5746f0b675ec217096628ca533a9468bd10e1b55dcd89793841269a3c78b22c6",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-ruff-postcommit.log"
        ): "82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-allowlist-postcommit.log"
        ): "684833d0e4a025d46fa1b91c7fe90ed53e8b98cecdb3b18c04f566e254d4026b",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-compileall-postcommit.log"
        ): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-diff-check-postcommit.log"
        ): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        (
            "jaa-single-codex-20260729/"
            "jaa10-phase-c-elapsed-cohort-status-postcommit.log"
        ): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    phase_c_evidence = {
        pointer["relative_path"]: pointer["sha256"]
        for pointer in _evidence_pointers(phase_c)
    }
    assert phase_c_evidence == expected_phase_c_evidence
    for relative_path, expected_sha256 in expected_phase_c_evidence.items():
        evidence_path = evidence_bases["operator_control_root"] / relative_path
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            expected_sha256
        )
        assert evidence_path.stat().st_mode & 0o777 == 0o444
    assert set(phase_c["deterministic_logs"]) == {
        "new_suites",
        "phase_b",
        "phase_a",
        "manifest_truth",
        "standing_jaa10_focused",
        "mutation_cohort",
        "standing_jaa09_real_vacancy",
        "ruff",
        "allowlist",
        "compileall",
        "diff_check",
        "clean_status",
    }
    assert {
        key: record["result"]
        for key, record in phase_c["deterministic_logs"].items()
    } == {
        "new_suites": "25 passed",
        "phase_b": "41 passed",
        "phase_a": "19 passed",
        "manifest_truth": "4 passed",
        "standing_jaa10_focused": "16 passed",
        "mutation_cohort": "14 passed",
        "standing_jaa09_real_vacancy": "32 passed",
        "ruff": "All checks passed!",
        "allowlist": "exact three add-only paths",
        "compileall": "empty_success",
        "diff_check": "empty_success",
        "clean_status": "empty_success",
    }
    assert all(
        record["mode"] == "0444"
        for record in phase_c["deterministic_logs"].values()
    )
    assert phase_c["strongest_claim"] == (
        "Bounded same-boot elapsed-cohort fixture rehearsal machinery is "
        "independently accepted; one bounded-local loopback-fixture cohort "
        "is OPEN under the accepted open_elapsed_cohort entry point at "
        "source 9246458d12f5907eaa87df49f33f259c2b9043a0 and has not "
        "been closed or collected; no elapsed threshold, calendar-time, "
        "signed-time, live external-vacancy, metric, production or slice "
        "claim is made."
    )
    assert phase_c["contamination_policy"] == (
        "cohort_outputs_are_locked_evidence_never_tuning_input_for_"
        "same_source_version"
    )
    assert phase_c["calendar_time_authentication"] == (
        "absent_same_boot_scope_only"
    )
    assert phase_c["external_time_attestation"] == "absent"
    assert phase_c["filesystem_privileged_writer_limit"] == (
        "surgical_partial_rewrite_undetectable_no_local_mitigation"
    )
    assert phase_c["kernel_time_witness_limit"] == (
        "same_boot_clock_boottime_honest_kernel_not_calendar_authenticated"
    )
    assert phase_c["objective_satisfied"] is False
    assert phase_c["metrics_evaluated"] is False
    assert phase_c["hard_quality_targets"] == {
        "ats_parse_success_bp": {
            "target": 10_000,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
        "confirmed_without_receipt": {
            "target": 0,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
        "deterministic_replay_mismatch": {
            "target": 0,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
        "duplicate_submissions": {
            "target": 0,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
        "ineligible_submissions": {
            "target": 0,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
        "released_employer_claims_without_citations": {
            "target": 0,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
        "unsupported_released_claims": {
            "target": 0,
            "status": "not_evaluable_from_elapsed_fixture_cohort",
        },
    }
    assert phase_c["live_time_separated_execution"] == "not_collected"
    assert phase_c["production_certification"] == "withheld"
    assert phase_c["withheld_reason"] == (
        "live_time_separated_shadow_and_metrics_not_evaluated"
    )
    assert phase_c["certifies_slice"] is False
    assert phase_c["external_action_capability"] is False
    assert phase_c["real_applications_submitted"] == 0
    assert phase_c["assessment"] == (
        "bounded_local_elapsed_cohort_fixture_rehearsal_accepted"
    )
    for authority in (
        "submission_authority",
        "release_token_authority",
        "credential_authority",
        "browser_network_authority",
    ):
        assert phase_c[authority] == "withheld"
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
    phase_a = jaa10["bounded_local_acceptance"][
        "observation_ledger_phase_a"
    ]
    assert phase_a["objective_satisfied"] is False
    assert phase_a["metrics_evaluated"] is False
    assert phase_a["live_time_separated_execution"] == "not_collected"
    assert phase_a["production_certification"] == "withheld"
    assert phase_a["withheld_reason"] == (
        "live_time_separated_shadow_and_metrics_not_evaluated"
    )
    assert phase_a["external_action_capability"] is False
    for key in (
        "submission_authority",
        "release_token_authority",
        "credential_authority",
    ):
        assert phase_a[key] == "withheld"
    phase_revision = phase_a["implemented_source_git_revision"]
    assert phase_revision == "68f0f245b58a3ad0180f4d49ecb086d29ee0e99f"
    assert _git(
        "rev-parse", f"{phase_revision}^{{tree}}"
    ).decode().strip() == phase_a["implemented_source_tree"]
    assert _git(
        "rev-parse", f"{phase_revision}^"
    ).decode().strip() == phase_a["implemented_source_parent"]
    assert _source_content_revision_at(phase_revision) == (
        phase_a["implemented_source_content_revision"]
    )
    assert subprocess.run(
        ("git", "merge-base", "--is-ancestor", phase_revision, "HEAD"),
        cwd=ROOT,
        check=False,
    ).returncode == 0
    for accepted_path in phase_a["accepted_paths"]:
        relative = accepted_path["path"]
        payload = _git("show", f"{phase_revision}:{relative}")
        assert hashlib.sha256(payload).hexdigest() == (
            accepted_path["sha256"]
        )
        assert _git(
            "rev-parse", f"{phase_revision}:{relative}"
        ) == _git("rev-parse", f"HEAD:{relative}")
    prior_truth = phase_a["prior_truth_transition"]
    assert prior_truth["source_git_revision"] == (
        phase_a["implemented_source_parent"]
    )
    assert _git(
        "rev-parse", f"{prior_truth['source_git_revision']}^{{tree}}"
    ).decode().strip() == prior_truth["source_tree"]
    assert _source_content_revision_at(
        prior_truth["source_git_revision"]
    ) == prior_truth["source_content_revision"]
    for pointer in _evidence_pointers(phase_a):
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    for record in (
        phase_a["sonnet_review"],
        phase_a["fable_exact_source_ruling"],
        *phase_a["deterministic_logs"].values(),
    ):
        assert record["mode"] == "0444"
        pointer = record["artifact"]
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.stat().st_mode & 0o777 == 0o444
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
    tests_by_id = {test["id"]: test for test in jaa10["tests"]}
    assert tests_by_id["JAA-10-observation-ledger"]["argv"] == [
        "{python}",
        "-m",
        "pytest",
        "-q",
        "test_jaa10_shadow_observation_ledger.py",
    ]
    assert tests_by_id[
        "JAA-10-observation-ledger-negative-controls"
    ]["argv"] == [
        "{python}",
        "-m",
        "pytest",
        "-q",
        "test_jaa10_shadow_observation_ledger_negative_controls.py",
    ]
    assert tests_by_id[
        "JAA-10-observation-ledger-negative-controls"
    ]["negative_control"] is True
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
    jaa11_contract = dict(jaa11["provisional_fixture_contract"])
    live_canary_authority = jaa11_contract.pop(
        "live_canary_operator_authority"
    )
    assert jaa11_contract == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "jaa11_fixture_adapter_identity_reconciled_with_standing_"
            "jaa10_shadow_contract_"
            "finalized_2026-07-31"
        ),
        "implemented_source_git_revision": (
            "545b9e6489abc33896021957214e98396645188c"
        ),
        "implemented_source_tree": (
            "890718412e31212b2306dbd710cbc8e389f96278"
        ),
        "implemented_source_content_revision": (
            "sha256:127cefe54cac785661cc704df66a6f335"
            "32fa98a15cb4501754f9d6ddb408f06"
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
        "adapter_identity_repair": {
            "phase_a_git_revision": (
                "545b9e6489abc33896021957214e98396645188c"
            ),
            "phase_a_parent_git_revision": (
                "7cebb831f457524b3eb1499d038e17caa86f0d6e"
            ),
            "phase_a_tree": (
                "890718412e31212b2306dbd710cbc8e389f96278"
            ),
            "phase_a_source_content_revision": (
                "sha256:127cefe54cac785661cc704df66a6f335"
                "32fa98a15cb4501754f9d6ddb408f06"
            ),
            "route_url": (
                "http://127.0.0.1:0/applications/"
                "graphcore-build-engineer"
            ),
            "route_policy_sha256": (
                "042de40c5633fe7f41c652d81fbce4502"
                "f2192d79b53c3492a928e592376ea1c"
            ),
            "adapter_contract_sha256": (
                "e4cb8ee1b416d75063bb70b72208a3554"
                "fb0ccc59998f6ff4d9ef44b3eced4e5"
            ),
            "changed_file_sha256": {
                "career_automation/official_ats_adapter.py": (
                    "c80f8281e7f5a531c423a31e48644a803"
                    "493673e10d0b45a9dbd458f11dea37a"
                ),
                "test_jaa11_independent_acceptance.py": (
                    "cbaaec9457b7f56195102eabe6c3301df"
                    "dae95b8924c6023ef3573cb0c302a87"
                ),
                "test_jaa11_negative_controls.py": (
                    "e9228c9fcbe56d67be90d40d198e8e627"
                    "b8d30590b49f59c66706e733f2e1e0a"
                ),
                "test_jaa11_durable_integration.py": (
                    "f81a23e2f58380e745c84e07b8ccf8da"
                    "2b37e5d4c8e2ffcb2b48761784c32bc7"
                ),
            },
            "evidence": {
                "design_ruling": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "fable-jaa11-adapter-identity-repair-"
                        "design-gate-raw.json"
                    ),
                    "sha256": (
                        "ab211873f82ea254d5db62deebfda6a08"
                        "c2cca887f39634e26086fd1af339521"
                    ),
                },
                "sonnet_phase_a_review": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "sonnet-jaa11-adapter-identity-repair-"
                        "phase-a-review-raw.json"
                    ),
                    "sha256": (
                        "5c9a778f410fd32d30abfe7377dc53620"
                        "475cfd3701b5f39247cacc4235ca39c"
                    ),
                },
                "phase_a_receipt": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "JAA11_ADAPTER_IDENTITY_REPAIR_"
                        "PHASE_A_RECEIPT.md"
                    ),
                    "sha256": (
                        "827f7f1cb70bd6eec2baeb8e2db207472"
                        "9d607cc01e18b03fa3eda9c3fafdb5c"
                    ),
                },
                "fable_phase_a_acceptance": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "fable-jaa11-adapter-identity-repair-"
                        "phase-a-exact-source-raw.json"
                    ),
                    "sha256": (
                        "5208b1369db53d06592608fac7a4d03d0"
                        "936e836d9cda817b79596a4c158f9b9"
                    ),
                },
                "focused_log": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "jaa11-adapter-identity-repair-phase-a-"
                        "focused.log"
                    ),
                    "sha256": (
                        "1b16c9e0a6485e078ab4b30bc47ff39b"
                        "8e72176c12e336941ce2136ced11db47"
                    ),
                },
                "downstream_log": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "jaa11-adapter-identity-repair-phase-a-"
                        "downstream.log"
                    ),
                    "sha256": (
                        "6f67b85acd94f59bdeb58b2dd36b9b37"
                        "fe38f7dd3b92ed8dce1af5ab14ee6b3d"
                    ),
                },
                "collect_only_log": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "jaa11-adapter-identity-repair-phase-a-"
                        "collect-only.log"
                    ),
                    "sha256": (
                        "a3c1386698d06fe7550236d76fa6fcd7c"
                        "c6d91e725484f8cb46e559dd35d02ca"
                    ),
                },
                "ruff_log": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "jaa11-adapter-identity-repair-phase-a-ruff.log"
                    ),
                    "sha256": (
                        "82b3e6a6c090a57601d22943bd23fca92"
                        "18d1031dbe5a7b754092f9a156b4f18"
                    ),
                },
                "pycompile_log": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "jaa11-adapter-identity-repair-phase-a-"
                        "pycompile.log"
                    ),
                    "sha256": (
                        "e3b0c44298fc1c149afbf4c8996fb924"
                        "27ae41e4649b934ca495991b7852b855"
                    ),
                },
                "postcommit_stale_truth_log": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "jaa11-adapter-identity-repair-phase-a-"
                        "postcommit-stale-truth.log"
                    ),
                    "sha256": (
                        "f8c7cfc4ed809a3f897d336396f6f149"
                        "a3b974e714910f1bcd8522a6c0545ede"
                    ),
                },
                "fable_phase_b_final_acceptance": {
                    "path_base": "operator_control_root",
                    "relative_path": (
                        "jaa-single-codex-20260729/"
                        "fable-jaa11-adapter-identity-repair-"
                        "phase-b-final-raw.json"
                    ),
                    "sha256": (
                        "7ad9053d7eb9316d694f1580005dcc6ec"
                        "aec761b18606b2e3c39fd4120ae099d"
                    ),
                },
            },
        },
    }
    assert live_canary_authority == {
        "status": (
            "bounded_local_authority_intake_phase_a_"
            "implemented_pending_exact_source_review"
        ),
        "scope": (
            "pure_data_authority_and_selection_contract_"
            "no_external_capability"
        ),
        "implemented_source_git_revision": (
            "22a37046af1a78e75dc520128ad98d46bb2946eb"
        ),
        "implemented_source_tree": (
            "afce9c089bd5710e20bd679bec9e222875195667"
        ),
        "implemented_source_content_revision": (
            "sha256:2eb6390a263a88045c5240e47b94ad9d"
            "fe7eb90551d13ea5685e95a0b653c34f"
        ),
        "accepted_source_files": [
            {
                "path": "career_automation/live_canary_authority.py",
                "sha256": (
                    "e48372dc4e414212bc86d2bc0ba21d9ec"
                    "75f80d12eeaa6e1dfc80179a958e1fc"
                ),
            },
            {
                "path": "test_jaa11_live_canary_authority_intake.py",
                "sha256": (
                    "5614eaf0d46e1b198d16315de6e004a04"
                    "8160f007d038a27b1d9ecce44f37309"
                ),
            },
            {
                "path": (
                    "test_jaa11_live_canary_authority_negative_controls.py"
                ),
                "sha256": (
                    "56bf956a5fc2f693b9279585fabdee7296"
                    "3900cd775b7d89b6faf701d63dfb7b"
                ),
            },
        ],
        "authority_document": {
            "path_base": "software_factory_root",
            "relative_path": (
                "giga-user/reports/"
                "JAA11_LIVE_CANARY_OPERATOR_AUTHORITY_2026-07-31.md"
            ),
            "sha256": (
                "b1cc3740a7d760ab905c27156bf8498bb"
                "7f03f8cfe5e9267b82e2ad6f2a9f77c"
            ),
        },
        "max_canaries": 1,
        "forbidden_rank_range": [1, 20],
        "minimum_selected_rank": 21,
        "ranked_snapshot_status": "not_collected",
        "selected_vacancy_status": "not_selected",
        "selection_contract": (
            "deterministic_caller_supplied_snapshot_and_"
            "vacancy_evidence_fail_closed"
        ),
        "authority_state_evaluator": (
            "pure_data_permitted_exhausted_withheld"
        ),
        "optional_marketing_consent": "declined",
        "fail_closed_triggers": [
            "account_creation",
            "captcha",
            "login",
            "mfa",
            "missing_approved_fact",
            "payment",
        ],
        "public_multi_vacancy_acquisition_authorized": False,
        "public_acquisition_authority": (
            "not_granted_referral_required"
        ),
        "operational_release": "withheld",
        "external_action_capability": False,
        "real_submission_authority": "withheld",
        "production_certification": "withheld",
        "objective_satisfied": False,
        "dependency_satisfied": False,
    }
    authority_pointer = live_canary_authority["authority_document"]
    authority_path = (
        evidence_bases[authority_pointer["path_base"]]
        / authority_pointer["relative_path"]
    )
    assert authority_path.is_file()
    assert hashlib.sha256(authority_path.read_bytes()).hexdigest() == (
        authority_pointer["sha256"]
    )
    authority_revision = live_canary_authority[
        "implemented_source_git_revision"
    ]
    assert _git(
        "rev-parse", f"{authority_revision}^{{tree}}"
    ).decode().strip() == live_canary_authority["implemented_source_tree"]
    assert _source_content_revision_at(authority_revision) == (
        live_canary_authority["implemented_source_content_revision"]
    )
    for item in live_canary_authority["accepted_source_files"]:
        assert hashlib.sha256(
            _git("show", f"{authority_revision}:{item['path']}")
        ).hexdigest() == item["sha256"]
    assert "certification" not in jaa11
    for pointer in jaa11["provisional_fixture_contract"][
        "adapter_identity_repair"
    ]["evidence"].values():
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
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
        "career_automation/live_canary_authority.py",
    ]
    assert [test["id"] for test in jaa11["tests"]] == [
        "JAA-11-contract",
        "JAA-11-negative-controls",
        "JAA-11-durable-circuit-contract",
        "JAA-11-durable-circuit-negative-controls",
        "JAA-11-durable-integration",
        "JAA-11-live-canary-authority-intake",
        "JAA-11-live-canary-authority-negative-controls",
    ]
    tests_by_id = {test["id"]: test for test in jaa11["tests"]}
    assert tests_by_id[
        "JAA-11-live-canary-authority-negative-controls"
    ]["negative_control"] is True
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
    jaa12_contract = dict(jaa12["provisional_local_export_contract"])
    status_store = jaa12_contract.pop("durable_status_evidence_store")
    status_coordinator = jaa12_contract.pop("durable_status_coordinator")
    typed_reads = jaa12_contract.pop("durable_typed_status_reads")
    fault_controls = jaa12_contract.pop(
        "durable_status_evidence_fault_controls"
    )
    assert jaa12_contract == {
        "status": "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
        "independent_fable_ratification": (
            "bounded_local_implementation_ratified_"
            "objective_unsatisfied_2026-07-30"
        ),
        "implemented_source_git_revision": (
            "545b9e6489abc33896021957214e98396645188c"
        ),
        "implemented_source_tree": (
            "890718412e31212b2306dbd710cbc8e389f96278"
        ),
        "implemented_source_content_revision": (
            "sha256:127cefe54cac785661cc704df66a6f335"
            "32fa98a15cb4501754f9d6ddb408f06"
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
    assert set(status_store) == {
        "status",
        "scope",
        "implemented_source_git_revision",
        "implemented_source_tree",
        "implemented_source_content_revision",
        "accepted_source_files",
        "external_action_capability",
        "objective_satisfied",
        "dependency_satisfied",
        "upstream_dependency_satisfied",
        "mailbox_connector_status",
        "portal_connector_status",
        "message_send_authority",
        "production_certification",
        "follow_up_reference_hashes",
        "design_gate",
        "sonnet_initial_review",
        "sonnet_post_repair_review",
        "phase_a_ruling_receipt",
        "deterministic_logs",
    }
    assert {
        key: status_store[key]
        for key in (
            "status",
            "scope",
            "implemented_source_git_revision",
            "implemented_source_tree",
            "implemented_source_content_revision",
            "external_action_capability",
            "objective_satisfied",
            "dependency_satisfied",
            "upstream_dependency_satisfied",
            "mailbox_connector_status",
            "portal_connector_status",
            "message_send_authority",
            "production_certification",
            "follow_up_reference_hashes",
        )
    } == {
        "status": "bounded_local_phase_a_accepted",
        "scope": "bounded_local_no_external_capability",
        "implemented_source_git_revision": (
            "55aabf3a9c93409627bb32b812ea6ec9b697b902"
        ),
        "implemented_source_tree": (
            "52ebe3d35500493a380c8e0cd40e7ba8430ce3fd"
        ),
        "implemented_source_content_revision": (
            "sha256:a4142e3195b083b117ee925346e4c0a"
            "7b3b37b1fbd9ac2226f96b36f7d398ced"
        ),
        "external_action_capability": False,
        "objective_satisfied": False,
        "dependency_satisfied": False,
        "upstream_dependency_satisfied": False,
        "mailbox_connector_status": "not_connected",
        "portal_connector_status": "not_connected",
        "message_send_authority": "withheld",
        "production_certification": "withheld",
        "follow_up_reference_hashes": (
            "caller_supplied_structural_references"
        ),
    }
    assert status_store["accepted_source_files"] == [
        {
            "path": "career_automation/status_evidence_store.py",
            "sha256": (
                "9b6965e2bc8dd92af171cb902e1317d0"
                "35e459ceb311a3443b7153f90a7a70ad"
            ),
        },
        {
            "path": "test_jaa12_status_evidence_store.py",
            "sha256": (
                "28e8fa0bb1f5c74a07b05f8fefae5819"
                "17f342c37b7923e09d21b62f1b2f0fb4"
            ),
        },
        {
            "path": (
                "test_jaa12_status_evidence_store_negative_controls.py"
            ),
            "sha256": (
                "36fbeebdd022724ac5a5c4ca28c45191"
                "7e35ca38383ecf5809fe2de83f495bb2"
            ),
        },
    ]
    assert set(status_store["design_gate"]) == {"prompt", "raw", "stderr"}
    assert set(status_store["sonnet_initial_review"]) == {
        "prompt",
        "raw",
        "stderr",
    }
    assert set(status_store["sonnet_post_repair_review"]) == {
        "prompt",
        "raw",
        "stderr",
    }
    assert set(status_store["deterministic_logs"]) == {
        "new_suites",
        "standing_jaa12",
        "manifest_truth",
        "downstream",
        "ruff",
        "pycompile",
        "diff_check",
        "identity",
    }
    status_store_pointers = {
        "design_gate_prompt": status_store["design_gate"]["prompt"],
        "design_gate_raw": status_store["design_gate"]["raw"],
        "design_gate_stderr": status_store["design_gate"]["stderr"],
        "sonnet_initial_prompt": (
            status_store["sonnet_initial_review"]["prompt"]
        ),
        "sonnet_initial_raw": (
            status_store["sonnet_initial_review"]["raw"]
        ),
        "sonnet_initial_stderr": (
            status_store["sonnet_initial_review"]["stderr"]
        ),
        "sonnet_post_repair_prompt": (
            status_store["sonnet_post_repair_review"]["prompt"]
        ),
        "sonnet_post_repair_raw": (
            status_store["sonnet_post_repair_review"]["raw"]
        ),
        "sonnet_post_repair_stderr": (
            status_store["sonnet_post_repair_review"]["stderr"]
        ),
        "phase_a_ruling_receipt": status_store["phase_a_ruling_receipt"],
        **status_store["deterministic_logs"],
    }
    assert {
        key: (pointer["relative_path"], pointer["sha256"])
        for key, pointer in status_store_pointers.items()
    } == {
        "design_gate_prompt": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-next-action-design-gate-prompt.txt",
            "ec4f61ae63a92bf252d514f62be0120d"
            "5ecce1d3f3f6cc9601b9f3ca18044375",
        ),
        "design_gate_raw": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-next-action-design-gate-raw.json",
            "97075f814b06f2d945a36bc259d53895"
            "b23237591a7b942b524bf8cb5523b0c2",
        ),
        "design_gate_stderr": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-next-action-design-gate-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "sonnet_initial_prompt": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-store-phase-a-review-prompt.txt",
            "6b388663b102a93cbec593d06f9b8664"
            "afaf3c9b1f8bbe1460b0aee458b4ac31",
        ),
        "sonnet_initial_raw": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-store-phase-a-review-raw.json",
            "5d18b2fbda8845d01bc7a4ce276ab69d"
            "f4e443efe1b77f232610724f4048936e",
        ),
        "sonnet_initial_stderr": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-store-phase-a-review-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "sonnet_post_repair_prompt": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-store-phase-a-post-repair-review-prompt.txt",
            "e340ffdcdf7f0cc4ae0ee23e705e1b31"
            "1f3ad98942b4cbddf541c80114207261",
        ),
        "sonnet_post_repair_raw": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-store-phase-a-post-repair-review-raw.json",
            "67e261a98daaa71f4f214c33fae50d1f"
            "c7d4a4bc44e2a67b3afdcb28c5a793b8",
        ),
        "sonnet_post_repair_stderr": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-store-phase-a-post-repair-review-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "phase_a_ruling_receipt": (
            "jaa-single-codex-20260729/"
            "FABLE_JAA12_STATUS_EVIDENCE_STORE_PHASE_A_ACCEPTANCE.md",
            "3068363b4d17d927bd5657afed51518b"
            "2b3c8f650f056f8497b70461bdf4c68f",
        ),
        "new_suites": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-new-suites.log",
            "d46812ffac4160476531cff55fb239fe3"
            "943bb5d993493d02f556e91c78fa676",
        ),
        "standing_jaa12": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-standing.log",
            "a6843f45b7441f6248914e0a0463a895"
            "58fe5e793f976b295c402ad5017f0a53",
        ),
        "manifest_truth": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-manifest-truth.log",
            "9b72d354883cf9c5acf6fb0fe8e9b3ce"
            "7dbc473c1486b74c23dfb269f24372f1",
        ),
        "downstream": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-downstream.log",
            "0867a7565ebae2b8ba2d15f7072b42e3"
            "9465e0d3c91e518c9d9dbcc6368f4580",
        ),
        "ruff": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-ruff.log",
            "82b3e6a6c090a57601d22943bd23fca9"
            "218d1031dbe5a7b754092f9a156b4f18",
        ),
        "pycompile": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-pycompile.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "diff_check": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-diff-check.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "identity": (
            "jaa-single-codex-20260729/"
            "jaa12-status-store-phase-a-postcommit-identity.log",
            "ac84af72d4c598856cfe6f9d56447067"
            "26cb2b678524a70ad97e67684cd1f9d4",
        ),
    }
    for pointer in status_store_pointers.values():
        assert pointer["path_base"] == "operator_control_root"
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert set(status_coordinator) == {
        "status",
        "implemented_source_git_revision",
        "implemented_source_tree",
        "implemented_source_content_revision",
        "coordinator_policy_sha256",
        "contract_sha256",
        "accepted_source_files",
        "partial_progress",
        "atomicity_across_steps",
        "durable_read_api",
        "follow_up_reference_hashes",
        "connector_authority",
        "mailbox_access",
        "portal_access",
        "send_authority",
        "objective_satisfied",
        "dependency_satisfied",
        "production_certification",
        "certifies_slice",
        "external_action_capability",
        "real_applications_submitted",
        "design_gate",
        "phase_a_postcommit_logs",
        "sonnet_phase_a_review",
        "phase_a_acceptance_receipt",
    }
    assert {
        key: status_coordinator[key]
        for key in (
            "status",
            "implemented_source_git_revision",
            "implemented_source_tree",
            "implemented_source_content_revision",
            "coordinator_policy_sha256",
            "contract_sha256",
            "partial_progress",
            "atomicity_across_steps",
            "durable_read_api",
            "follow_up_reference_hashes",
            "connector_authority",
            "mailbox_access",
            "portal_access",
            "send_authority",
            "objective_satisfied",
            "dependency_satisfied",
            "production_certification",
            "certifies_slice",
            "external_action_capability",
            "real_applications_submitted",
        )
    } == {
        "status": "bounded_local_coordinator_phase_a_accepted",
        "implemented_source_git_revision": (
            "d5f2f99f8165aabf53132eb3e6451a8b7a5eab79"
        ),
        "implemented_source_tree": (
            "bd8f472ddfff19bd41df92febe7bfb3d42252570"
        ),
        "implemented_source_content_revision": (
            "sha256:62c56f95a0439c29bb504ffc9a2d7db5"
            "756710e519e0443a0154174832058f91"
        ),
        "coordinator_policy_sha256": (
            "1c3874eaea9df15413984923f871aa13"
            "55a46b4fa5e0263b8c41f0d42b6383bd"
        ),
        "contract_sha256": (
            "bbeb6b6d8ac47b33898626e98f703faa"
            "67bc556a6e3814e3f53d756b12a0e327"
        ),
        "partial_progress": "truthful_receipted_steps",
        "atomicity_across_steps": "absent",
        "durable_read_api": "absent",
        "follow_up_reference_hashes": (
            "caller_supplied_structural_references"
        ),
        "connector_authority": "withheld",
        "mailbox_access": "withheld",
        "portal_access": "withheld",
        "send_authority": "withheld",
        "objective_satisfied": False,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }
    assert status_coordinator["accepted_source_files"] == [
        {
            "path": "career_automation/status_store_coordinator.py",
            "sha256": (
                "c521848d7f379a900dad50f9c4d99149"
                "8ba6eea59a627897eb517cde6462d72c"
            ),
        },
        {
            "path": "test_jaa12_status_store_coordinator.py",
            "sha256": (
                "3263b55bcf51fa66295a18a486d4fed3"
                "e26226fcabd6fc7ef86fe77cd1ec556e"
            ),
        },
        {
            "path": (
                "test_jaa12_status_store_coordinator_negative_controls.py"
            ),
            "sha256": (
                "bafdb8fe479bb779650061c0e84721cd"
                "160764bb8b325068abee0de249991723"
            ),
        },
    ]
    assert set(status_coordinator["design_gate"]) == {
        "prompt",
        "raw",
        "stderr",
    }
    assert set(status_coordinator["phase_a_postcommit_logs"]) == {
        "new_suites",
        "standing_jaa12",
        "manifest_truth",
        "ruff",
        "pycompile",
        "allowlist",
        "identity",
    }
    assert set(status_coordinator["sonnet_phase_a_review"]) == {
        "prompt",
        "raw",
        "stderr",
    }
    coordinator_pointers = {
        "design_prompt": status_coordinator["design_gate"]["prompt"],
        "design_raw": status_coordinator["design_gate"]["raw"],
        "design_stderr": status_coordinator["design_gate"]["stderr"],
        **status_coordinator["phase_a_postcommit_logs"],
        "sonnet_prompt": (
            status_coordinator["sonnet_phase_a_review"]["prompt"]
        ),
        "sonnet_raw": status_coordinator["sonnet_phase_a_review"]["raw"],
        "sonnet_stderr": (
            status_coordinator["sonnet_phase_a_review"]["stderr"]
        ),
        "phase_a_acceptance_receipt": (
            status_coordinator["phase_a_acceptance_receipt"]
        ),
    }
    assert {
        key: (pointer["relative_path"], pointer["sha256"])
        for key, pointer in coordinator_pointers.items()
    } == {
        "design_prompt": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durable-ingestion-integration-design-gate-prompt.txt",
            "2b278662d1751c14aa806ea6f06c7b63"
            "2f8c0d14fd864f6fb39f8f5466d4345f",
        ),
        "design_raw": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durable-ingestion-integration-design-gate-raw.json",
            "961fb134ba0314933f46d99768ad801c"
            "36d1b00d5a7963d8af6c59c26df35908",
        ),
        "design_stderr": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durable-ingestion-integration-design-gate-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "new_suites": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-new-suites.log",
            "cf38a20665d2d870cf1d74ceebd187ab"
            "669f1ec4e6085b63d9a4fd8ac050e1dd",
        ),
        "standing_jaa12": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-standing.log",
            "ec6f469ae5231b357cee6ed2d0ea8ac0"
            "3abca2e07b108bbac7d021ca238a4ecf",
        ),
        "manifest_truth": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-manifest-truth.log",
            "03da38b2466e69b11a94af917faab419"
            "e5b45caa97a278e133cc767e94781913",
        ),
        "ruff": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-ruff.log",
            "82b3e6a6c090a57601d22943bd23fca9"
            "218d1031dbe5a7b754092f9a156b4f18",
        ),
        "pycompile": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-pycompile.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "allowlist": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-allowlist.log",
            "52871b8f457617ba4dd967fa90813a579"
            "8b55b292e148f1fce712ae843681146",
        ),
        "identity": (
            "jaa-single-codex-20260729/"
            "jaa12-status-coordinator-phase-a-postcommit-identity.log",
            "5531a72144191263d85c5f53ae7d041d"
            "a1f1bb73b936169fbe641beac739c8a3",
        ),
        "sonnet_prompt": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-coordinator-phase-a-review-prompt.txt",
            "9a6654ee51030391e56c7c77a31d90cc"
            "cb6605a6f4917d96419fd9372b6a8a06",
        ),
        "sonnet_raw": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-coordinator-phase-a-review-raw.json",
            "7d72d712bd6deab29eaec5e2465d6c7"
            "42f16f8857aa5ba7012b38bf4bb98ebdd",
        ),
        "sonnet_stderr": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-coordinator-phase-a-review-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "phase_a_acceptance_receipt": (
            "jaa-single-codex-20260729/"
            "FABLE_JAA12_STATUS_COORDINATOR_PHASE_A_ACCEPTANCE.md",
            "c90f2ad7ad0c13c577653c5ed075ff94"
            "a76bc86c943a2e817674413bcd85c262",
        ),
    }
    for pointer in coordinator_pointers.values():
        assert pointer["path_base"] == "operator_control_root"
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert set(typed_reads) == {
        "status",
        "scope",
        "implemented_source_git_revision",
        "implemented_source_tree",
        "implemented_source_content_revision",
        "accepted_source_files",
        "upstream_dependency_satisfied",
        "follow_up_reference_hashes",
        "atomicity_across_steps",
        "connector_authority",
        "mailbox_connector_status",
        "portal_connector_status",
        "mailbox_access",
        "portal_access",
        "send_authority",
        "objective_satisfied",
        "dependency_satisfied",
        "production_certification",
        "certifies_slice",
        "external_action_capability",
        "real_applications_submitted",
        "design_gate",
        "sonnet_initial_review",
        "sonnet_post_repair_review",
        "phase_a_exact_source_gate",
        "phase_a_acceptance_receipt",
        "deterministic_logs",
    }
    assert {
        key: typed_reads[key]
        for key in (
            "status",
            "scope",
            "implemented_source_git_revision",
            "implemented_source_tree",
            "implemented_source_content_revision",
            "upstream_dependency_satisfied",
            "follow_up_reference_hashes",
            "atomicity_across_steps",
            "connector_authority",
            "mailbox_connector_status",
            "portal_connector_status",
            "mailbox_access",
            "portal_access",
            "send_authority",
            "objective_satisfied",
            "dependency_satisfied",
            "production_certification",
            "certifies_slice",
            "external_action_capability",
            "real_applications_submitted",
        )
    } == {
        "status": "bounded_local_typed_reads_phase_a_accepted",
        "scope": "bounded_local_no_external_capability",
        "implemented_source_git_revision": (
            "37d41f1b68bcd7684066ecaaef748114a907c538"
        ),
        "implemented_source_tree": (
            "21dd386a2024e86a77cb54aede0eb357dcdf5b38"
        ),
        "implemented_source_content_revision": (
            "sha256:1c6c366e12c9dd42a3a91176ff08f40"
            "9e7578767374c9e8ef57a418ecb562b56"
        ),
        "upstream_dependency_satisfied": False,
        "follow_up_reference_hashes": (
            "caller_supplied_structural_references"
        ),
        "atomicity_across_steps": "absent",
        "connector_authority": "withheld",
        "mailbox_connector_status": "not_connected",
        "portal_connector_status": "not_connected",
        "mailbox_access": "withheld",
        "portal_access": "withheld",
        "send_authority": "withheld",
        "objective_satisfied": False,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }
    assert typed_reads["accepted_source_files"] == [
        {
            "path": "career_automation/status_evidence_store.py",
            "sha256": (
                "13fba08fbd51beb07ee03e3e87a7df94"
                "69bda7ca916783a1299e1b50b9c0a732"
            ),
        },
        {
            "path": "test_jaa12_status_evidence_reader.py",
            "sha256": (
                "2788fe875601701004ff8dd2e9809489"
                "d6a26e846adf87243e5403a43ba6944b"
            ),
        },
        {
            "path": (
                "test_jaa12_status_evidence_reader_negative_controls.py"
            ),
            "sha256": (
                "1445492bd071c41670f11d3738a1ccb3"
                "88763b794d8c3d67ef5d8b087c5fc429"
            ),
        },
    ]
    assert {
        key: typed_reads[key]["disposition"]
        for key in (
            "design_gate",
            "sonnet_initial_review",
            "sonnet_post_repair_review",
            "phase_a_exact_source_gate",
        )
    } == {
        "design_gate": "AUTHORIZE_BOUNDED_IMPLEMENTATION",
        "sonnet_initial_review": "ACCEPT_WITH_FINDINGS",
        "sonnet_post_repair_review": "ACCEPT",
        "phase_a_exact_source_gate": "ACCEPT_AND_AUTHORIZE_PHASE_B",
    }
    for key in (
        "design_gate",
        "sonnet_initial_review",
        "sonnet_post_repair_review",
        "phase_a_exact_source_gate",
    ):
        assert set(typed_reads[key]) == {
            "disposition",
            "prompt",
            "raw",
            "stderr",
        }
    assert set(typed_reads["deterministic_logs"]) == {
        "new_suites",
        "standing_jaa12",
        "downstream",
        "truth_stale",
        "ruff",
        "pycompile",
        "diff_check",
        "allowlist",
        "identity",
    }
    typed_read_pointers = {
        "design_prompt": typed_reads["design_gate"]["prompt"],
        "design_raw": typed_reads["design_gate"]["raw"],
        "design_stderr": typed_reads["design_gate"]["stderr"],
        "sonnet_initial_prompt": (
            typed_reads["sonnet_initial_review"]["prompt"]
        ),
        "sonnet_initial_raw": typed_reads["sonnet_initial_review"]["raw"],
        "sonnet_initial_stderr": (
            typed_reads["sonnet_initial_review"]["stderr"]
        ),
        "sonnet_post_repair_prompt": (
            typed_reads["sonnet_post_repair_review"]["prompt"]
        ),
        "sonnet_post_repair_raw": (
            typed_reads["sonnet_post_repair_review"]["raw"]
        ),
        "sonnet_post_repair_stderr": (
            typed_reads["sonnet_post_repair_review"]["stderr"]
        ),
        "phase_a_exact_source_prompt": (
            typed_reads["phase_a_exact_source_gate"]["prompt"]
        ),
        "phase_a_exact_source_raw": (
            typed_reads["phase_a_exact_source_gate"]["raw"]
        ),
        "phase_a_exact_source_stderr": (
            typed_reads["phase_a_exact_source_gate"]["stderr"]
        ),
        "phase_a_acceptance_receipt": (
            typed_reads["phase_a_acceptance_receipt"]
        ),
        **typed_reads["deterministic_logs"],
    }
    assert {
        key: (pointer["relative_path"], pointer["sha256"])
        for key, pointer in typed_read_pointers.items()
    } == {
        "design_prompt": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durable-read-recovery-design-gate-prompt.txt",
            "b6146df7ccc1515bff67a26c261b9752"
            "edd4454940f3063c197969d39acbdb9d",
        ),
        "design_raw": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durable-read-recovery-design-gate-raw.json",
            "2a8ef1a4e7cb53693f9904ae9ba0fffe"
            "831a6a0044a87b3a248ea45e3a98e0bc",
        ),
        "design_stderr": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durable-read-recovery-design-gate-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "sonnet_initial_prompt": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-reader-phase-a-review-prompt.txt",
            "b2c12f8b06ec5b042afbdf600284445f"
            "3b65971f252ae6355fd96fc98c083f8e",
        ),
        "sonnet_initial_raw": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-reader-phase-a-review-raw.json",
            "a988febf628f7fa865ab88b96ae2a741b"
            "850b8330d622f682355aec3cb4fef21",
        ),
        "sonnet_initial_stderr": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-reader-phase-a-review-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "sonnet_post_repair_prompt": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-reader-phase-a-postrepair-review-prompt.txt",
            "a605e958b00293f3ddeb23d8c61de985"
            "f8b61bf575a8bc637b271d85fee05320",
        ),
        "sonnet_post_repair_raw": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-reader-phase-a-postrepair-review-raw.json",
            "5a4c5f5388ac463ca926ea10cddde05b"
            "b66e059e5bfe6fef7c496515d6357d4f",
        ),
        "sonnet_post_repair_stderr": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-status-reader-phase-a-postrepair-review-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "phase_a_exact_source_prompt": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-status-reader-phase-a-exact-source-prompt.txt",
            "124d9dea2c69b6da3eec4acb17c2ce04"
            "cce9e7fd644409bb4c7f491a8f922b5b",
        ),
        "phase_a_exact_source_raw": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-status-reader-phase-a-exact-source-raw.json",
            "5bfa84832416b93f163269ea12d473975"
            "2a11bda66f6f12fc5d34e945013f0fa",
        ),
        "phase_a_exact_source_stderr": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-status-reader-phase-a-exact-source-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "phase_a_acceptance_receipt": (
            "jaa-single-codex-20260729/"
            "FABLE_JAA12_DURABLE_TYPED_READ_PHASE_A_ACCEPTANCE.md",
            "4e46e22ed454dc3b48668e176b91d98f"
            "bd2852d754aa01e27e729459f665e2ba",
        ),
        "new_suites": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-new-suites.log",
            "b99f6ebf790c8ed7dc780f516066540c"
            "0ac691a26cfb6152026bb7d4d37a265f",
        ),
        "standing_jaa12": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-standing.log",
            "43686a0e54a2d7726fcf2ed91abe6333"
            "d277c205733005cd52d238a85ea7aac4",
        ),
        "downstream": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-downstream.log",
            "738de28bf7dede0efb71f64b6a8b55e"
            "5dbcb739885bab9336601ff70556f2f17",
        ),
        "truth_stale": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-truth-stale.log",
            "b8905ee1ad928bf5653960624af5db102"
            "1d4866d7f8490bab42aa49a81909408",
        ),
        "ruff": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-ruff.log",
            "82b3e6a6c090a57601d22943bd23fca9"
            "218d1031dbe5a7b754092f9a156b4f18",
        ),
        "pycompile": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-pycompile.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "diff_check": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-diff-check.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "allowlist": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-allowlist.log",
            "d41aac0f9766e7ec186df9da3f7a3861"
            "c3be4f23f4ed33973582c03d879badb8",
        ),
        "identity": (
            "jaa-single-codex-20260729/"
            "jaa12-status-reader-phase-a-postrepair-identity.log",
            "5456c43df9f617b9b603db25a63e4d7e"
            "6ad5724c1242dd2318942fbff7a91972",
        ),
    }
    for pointer in typed_read_pointers.values():
        assert pointer["path_base"] == "operator_control_root"
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
    assert set(fault_controls) == {
        "status",
        "scope",
        "implemented_source_git_revision",
        "implemented_source_tree",
        "implemented_source_content_revision",
        "accepted_source_files",
        "tested_boundaries",
        "upstream_dependency_satisfied",
        "follow_up_reference_hashes",
        "atomicity_across_steps",
        "connector_authority",
        "mailbox_connector_status",
        "portal_connector_status",
        "mailbox_access",
        "portal_access",
        "send_authority",
        "objective_satisfied",
        "dependency_satisfied",
        "production_certification",
        "certifies_slice",
        "external_action_capability",
        "real_applications_submitted",
        "design_gate",
        "sonnet_exact_source_review",
        "phase_a_exact_source_gate",
        "phase_a_acceptance_receipt",
        "deterministic_logs",
    }
    assert {
        key: fault_controls[key]
        for key in (
            "status",
            "scope",
            "implemented_source_git_revision",
            "implemented_source_tree",
            "implemented_source_content_revision",
            "upstream_dependency_satisfied",
            "follow_up_reference_hashes",
            "atomicity_across_steps",
            "connector_authority",
            "mailbox_connector_status",
            "portal_connector_status",
            "mailbox_access",
            "portal_access",
            "send_authority",
            "objective_satisfied",
            "dependency_satisfied",
            "production_certification",
            "certifies_slice",
            "external_action_capability",
            "real_applications_submitted",
        )
    } == {
        "status": (
            "bounded_local_test_only_fault_controls_phase_a_accepted"
        ),
        "scope": "bounded_local_no_external_capability",
        "implemented_source_git_revision": (
            "5ea2fdccef1851d2b7d4605feb7e99c0e4080406"
        ),
        "implemented_source_tree": (
            "68ff93f2c5f2d9937c6cdc5ff6667f56449234bf"
        ),
        "implemented_source_content_revision": (
            "sha256:af5b036118893538e9fd55b5beb0b349"
            "2491ed4252ca6a7c69da0c74947428f9"
        ),
        "upstream_dependency_satisfied": False,
        "follow_up_reference_hashes": (
            "caller_supplied_structural_references"
        ),
        "atomicity_across_steps": "absent",
        "connector_authority": "withheld",
        "mailbox_connector_status": "not_connected",
        "portal_connector_status": "not_connected",
        "mailbox_access": "withheld",
        "portal_access": "withheld",
        "send_authority": "withheld",
        "objective_satisfied": False,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }
    assert fault_controls["accepted_source_files"] == [
        {
            "path": "test_jaa12_status_evidence_durability_faults.py",
            "sha256": (
                "2227daa3836e8f40810a350c1abfa63d"
                "91db91e4a26b5caa5bfabcc42aedf1cd"
            ),
        }
    ]
    assert fault_controls["tested_boundaries"] == [
        "fail_closed_detection_of_physical_sqlite_corruption",
        (
            "sqlite_transactional_rollback_atomicity_under_"
            "injected_in_transaction_fault"
        ),
        (
            "snapshot_isolation_of_in_flight_typed_reads_under_"
            "committed_wal_append"
        ),
    ]
    assert {
        key: fault_controls[key]["disposition"]
        for key in (
            "design_gate",
            "sonnet_exact_source_review",
            "phase_a_exact_source_gate",
        )
    } == {
        "design_gate": "AUTHORIZE_TEST_ONLY_PHASE_A",
        "sonnet_exact_source_review": "ACCEPT",
        "phase_a_exact_source_gate": "ACCEPT_AND_AUTHORIZE_PHASE_B",
    }
    for key in (
        "design_gate",
        "sonnet_exact_source_review",
        "phase_a_exact_source_gate",
    ):
        assert set(fault_controls[key]) == {
            "disposition",
            "prompt",
            "raw",
            "stderr",
        }
    assert set(fault_controls["deterministic_logs"]) == {
        "new_suite",
        "standing_jaa12",
        "downstream",
        "ruff",
        "pycompile",
        "diff_check",
        "allowlist",
        "identity",
    }
    fault_control_pointers = {
        "design_prompt": fault_controls["design_gate"]["prompt"],
        "design_raw": fault_controls["design_gate"]["raw"],
        "design_stderr": fault_controls["design_gate"]["stderr"],
        "sonnet_prompt": (
            fault_controls["sonnet_exact_source_review"]["prompt"]
        ),
        "sonnet_raw": fault_controls["sonnet_exact_source_review"]["raw"],
        "sonnet_stderr": (
            fault_controls["sonnet_exact_source_review"]["stderr"]
        ),
        "phase_a_prompt": (
            fault_controls["phase_a_exact_source_gate"]["prompt"]
        ),
        "phase_a_raw": (
            fault_controls["phase_a_exact_source_gate"]["raw"]
        ),
        "phase_a_stderr": (
            fault_controls["phase_a_exact_source_gate"]["stderr"]
        ),
        "phase_a_acceptance_receipt": (
            fault_controls["phase_a_acceptance_receipt"]
        ),
        **fault_controls["deterministic_logs"],
    }
    assert {
        key: (pointer["relative_path"], pointer["sha256"])
        for key, pointer in fault_control_pointers.items()
    } == {
        "design_prompt": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-status-reader-durability-hardening-"
            "design-gate-prompt.txt",
            "c441cb85eeb8d2ea10999ec228fd3236f"
            "da407e0d3b5999493ea07eeb8b770a5",
        ),
        "design_raw": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-status-reader-durability-hardening-"
            "design-gate-raw.json",
            "cb6a311b2f9fdc9c96f85edeb3ffd969"
            "7329fd14f6074ad05d34768112472036",
        ),
        "design_stderr": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-status-reader-durability-hardening-"
            "design-gate-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "sonnet_prompt": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-durability-hardening-phase-a-review-prompt.txt",
            "bd10a5f4c811782aa474a1a2c8ac4426"
            "263eb3f3a8b7aa776ea0255954c734bf",
        ),
        "sonnet_raw": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-durability-hardening-phase-a-review-raw.json",
            "da1358a07a7532836a8312de300b0d4d6"
            "c83729b183f750464289cf16907626f",
        ),
        "sonnet_stderr": (
            "jaa-single-codex-20260729/"
            "sonnet-jaa12-durability-hardening-phase-a-review-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "phase_a_prompt": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durability-hardening-phase-a-"
            "exact-source-prompt.txt",
            "31574b9cb44dd29e4e53924f460b10395"
            "ce9fdc9f0617f6d0703f61a991f49c3",
        ),
        "phase_a_raw": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durability-hardening-phase-a-"
            "exact-source-raw.json",
            "76f7fbeeaae291c780c6d016c55d15056"
            "b29ce277d75f39bb761a5b46aedd73d",
        ),
        "phase_a_stderr": (
            "jaa-single-codex-20260729/"
            "fable-jaa12-durability-hardening-phase-a-"
            "exact-source-stderr.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "phase_a_acceptance_receipt": (
            "jaa-single-codex-20260729/"
            "FABLE_JAA12_DURABILITY_HARDENING_PHASE_A_ACCEPTANCE.md",
            "b36c9412ab3eb1fb6ece005e2b2c7daf"
            "1c588b60c18c509031c47ed68d25716f",
        ),
        "new_suite": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-"
            "new-suite.log",
            "625cd9db075f0d063982baf4c6b81448"
            "44ffe79aa412f50047a80fc4dcddb921",
        ),
        "standing_jaa12": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-standing.log",
            "7c6056cf2d90910b4263e67703f7890e"
            "c04062ca49a47d5b2c7b3a80df17eb2b",
        ),
        "downstream": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-downstream.log",
            "f48d2d3a0714e7bb16afb72d45d4ecfd"
            "091f663cbf38dd44f6162cd1d4a8ca35",
        ),
        "ruff": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-ruff.log",
            "82b3e6a6c090a57601d22943bd23fca9"
            "218d1031dbe5a7b754092f9a156b4f18",
        ),
        "pycompile": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-pycompile.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "diff_check": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-"
            "diff-check.log",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        "allowlist": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-allowlist.log",
            "ad72b7a240f86380e6cfddfa58ccd1780"
            "3cb6678ebce8479adf33a8991a0cbe0",
        ),
        "identity": (
            "jaa-single-codex-20260729/"
            "jaa12-durability-hardening-phase-a-postcommit-identity.log",
            "4435200c0c7b01db0b667ec2b0c8f0d"
            "d1258caba45304f026303b5d9c23393b6",
        ),
    }
    for pointer in fault_control_pointers.values():
        assert pointer["path_base"] == "operator_control_root"
        evidence_path = (
            evidence_bases[pointer["path_base"]]
            / pointer["relative_path"]
        )
        assert evidence_path.is_file()
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == (
            pointer["sha256"]
        )
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
    assert jaa12["owns"] == [
        "career_automation/status_ingestion.py",
        "career_automation/status_evidence_store.py",
        "career_automation/status_store_coordinator.py",
    ]
    assert [test["id"] for test in jaa12["tests"]] == [
        "JAA-12-contract",
        "JAA-12-negative-controls",
        "JAA-12-status-evidence-store",
        "JAA-12-status-evidence-store-negative-controls",
        "JAA-12-status-store-coordinator",
        "JAA-12-status-store-coordinator-negative-controls",
        "JAA-12-status-evidence-reader",
        "JAA-12-status-evidence-reader-negative-controls",
        "JAA-12-status-evidence-durability-faults",
    ]
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
            "545b9e6489abc33896021957214e98396645188c"
        ),
        "implemented_source_tree": (
            "890718412e31212b2306dbd710cbc8e389f96278"
        ),
        "implemented_source_content_revision": (
            "sha256:127cefe54cac785661cc704df66a6f335"
            "32fa98a15cb4501754f9d6ddb408f06"
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
            "545b9e6489abc33896021957214e98396645188c",
            "890718412e31212b2306dbd710cbc8e389f96278",
            "sha256:127cefe54cac785661cc704df66a6f335"
            "32fa98a15cb4501754f9d6ddb408f06",
        ),
        "JAA-12": (
            "545b9e6489abc33896021957214e98396645188c",
            "890718412e31212b2306dbd710cbc8e389f96278",
            "sha256:127cefe54cac785661cc704df66a6f335"
            "32fa98a15cb4501754f9d6ddb408f06",
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
            "545b9e6489abc33896021957214e98396645188c",
            "890718412e31212b2306dbd710cbc8e389f96278",
            "sha256:127cefe54cac785661cc704df66a6f335"
            "32fa98a15cb4501754f9d6ddb408f06",
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
            "jaa11_fixture_adapter_identity_reconciled_with_standing_"
            "jaa10_shadow_contract_"
            "finalized_2026-07-31"
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
        phase_path_revisions: dict[str, str] = {}
        if slice_id == "JAA-10":
            phase = block["observation_ledger_phase_a"]
            phase_path_revisions.update(
                {
                    item["path"]: phase["implemented_source_git_revision"]
                    for item in phase["accepted_paths"]
                }
            )
        if slice_id == "JAA-11":
            phase = block["live_canary_operator_authority"]
            phase_path_revisions.update(
                {
                    item["path"]: phase["implemented_source_git_revision"]
                    for item in phase["accepted_source_files"]
                }
            )
        if slice_id == "JAA-12":
            phase = block["durable_status_evidence_store"]
            phase_path_revisions.update(
                {
                    item["path"]: phase["implemented_source_git_revision"]
                    for item in phase["accepted_source_files"]
                }
            )
            phase = block["durable_status_coordinator"]
            phase_path_revisions.update(
                {
                    item["path"]: phase["implemented_source_git_revision"]
                    for item in phase["accepted_source_files"]
                }
            )
            phase = block["durable_typed_status_reads"]
            phase_path_revisions.update(
                {
                    item["path"]: phase["implemented_source_git_revision"]
                    for item in phase["accepted_source_files"]
                }
            )
            phase = block["durable_status_evidence_fault_controls"]
            phase_path_revisions.update(
                {
                    item["path"]: phase["implemented_source_git_revision"]
                    for item in phase["accepted_source_files"]
                }
            )
        for relative in declared_paths:
            path_revision = phase_path_revisions.get(relative, revision)
            assert _git(
                "rev-parse", f"{path_revision}:{relative}"
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
