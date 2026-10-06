from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from market_aligner.llm.codex_gateway import CodexSemanticGateway
from market_aligner.llm.contracts import canonical_hash
from market_aligner.profiler.current_activation import (
    PinnedRecoveryInputs,
    compile_current_profile_activation,
    write_current_activation_artifact,
)
from market_aligner.profiler.schema import CandidateProfile, EvidenceItem, TrackProfile
from market_aligner.profiler.store import ProfileStore


_APPROVAL = "synthetic-operator-approval"
_PROFILE_ID = "prf_" + "7" * 32


class ActivationRunner:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls = 0
        self.prompt = ""

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls += 1
        self.prompt = kwargs["input"]
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


class ContextAwareActivationRunner(ActivationRunner):
    def __init__(self) -> None:
        super().__init__({})
        self.profile_context: dict[str, Any] = {}
        self.profile_context_sha256 = ""

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        prompt = kwargs["input"]
        marker = "Exact task input JSON:\n"
        assert marker in prompt
        task_input = json.loads(prompt.rsplit(marker, 1)[1])
        context = task_input["profile_context"]
        encoded = json.dumps(
            context, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        assert task_input["profile_context_sha256"] == hashlib.sha256(encoded).hexdigest()
        assert context["exclusions"] == [
            "Do not use the sample-dataset project as candidate experience."
        ]
        assert context["constraints"] == {"evidence_scope": "synthetic coursework only"}
        self.profile_context = context
        self.profile_context_sha256 = task_input["profile_context_sha256"]
        self.response = {
            "selection": [
                {
                    "evidence_id": "ev-other",
                    "proof_class": "work_artifact",
                    "document_targets": ["cv", "cover_letter"],
                }
            ],
            "excluded_ids": ["ev-correction", "ev-current", "ev-old"],
            "correction_assessments": [
                {
                    "source_evidence_id": "ev-correction",
                    "relationship": "corrects",
                    "affected_evidence_ids": ["ev-old"],
                }
            ],
        }
        return super().__call__(command, **kwargs)


def _fixture(
    tmp_path: Path,
    *,
    constraints: dict[str, Any] | None = None,
    blind_spots: tuple[str, ...] = (),
    unknowns: tuple[str, ...] = (),
    exclusions: tuple[str, ...] = (),
) -> tuple[ProfileStore, bytes, bytes, bytes, str]:
    data_home = tmp_path / "data-home"
    data_home.mkdir(mode=0o700)
    evidence = [
        EvidenceItem(
            evidence_id="ev-correction",
            kind="work_history_correction",
            claim="Synthetic correction for ev-old: use the bounded project scope.",
            source_ref="synthetic://correction",
            status="explicit",
            confidence=1.0,
        ),
        EvidenceItem(
            evidence_id="ev-current",
            kind="project",
            claim="Completed a synthetic project over a sample dataset.",
            source_ref="synthetic://current",
            status="verified",
            confidence=0.9,
        ),
        EvidenceItem(
            evidence_id="ev-old",
            kind="project",
            claim="Synthetic old claim with an unsupported scale.",
            source_ref="synthetic://old",
            status="explicit",
            confidence=0.8,
        ),
        EvidenceItem(
            evidence_id="ev-other",
            kind="project",
            claim="Completed a separate synthetic unit-test exercise.",
            source_ref="synthetic://other",
            status="verified",
            confidence=0.8,
        ),
    ]
    profile = CandidateProfile(
        profile_id=_PROFILE_ID,
        version="synthetic-current-v1",
        constraints=constraints or {},
        blind_spots=blind_spots,
        unknowns=unknowns,
        exclusions=exclusions,
        tracks={
            "synthetic-track": TrackProfile(
                interest=1.0,
                demonstrated_skill=1.0,
                confidence=1.0,
                market_readiness=1.0,
                evidence_ids=tuple(item.evidence_id for item in evidence),
            )
        },
    )
    profile_bytes = yaml.safe_dump(
        asdict(profile), sort_keys=False, allow_unicode=True, width=100
    ).encode("utf-8")
    evidence_bytes = "".join(
        json.dumps(asdict(item), ensure_ascii=False, sort_keys=True) + "\n"
        for item in sorted(evidence, key=lambda item: item.evidence_id)
    ).encode("utf-8")
    store = ProfileStore(data_home)
    store.save(profile, evidence)
    approved_dir = data_home / "recovered-inputs" / "synthetic-approval"
    profile_dir = approved_dir / "profile"
    profile_dir.mkdir(parents=True, mode=0o700)
    for directory in (data_home / "recovered-inputs", approved_dir, profile_dir):
        directory.chmod(0o700)
    (profile_dir / "profile.yaml").write_bytes(profile_bytes)
    (profile_dir / "evidence.jsonl").write_bytes(evidence_bytes)
    (profile_dir / "profile.yaml").chmod(0o600)
    (profile_dir / "evidence.jsonl").chmod(0o600)
    descriptors = [
        {
            "kind": "candidate_profile_and_job_preferences",
            "destination_relative": "profile/profile.yaml",
            "sha256": hashlib.sha256(profile_bytes).hexdigest(),
            "bytes": len(profile_bytes),
            "source_path": "/never-open-this-synthetic-source",
        },
        {
            "kind": "existing_profile_claims_and_provenance",
            "destination_relative": "profile/evidence.jsonl",
            "sha256": hashlib.sha256(evidence_bytes).hexdigest(),
            "bytes": len(evidence_bytes),
            "source_path": "/never-open-this-synthetic-source-either",
        },
    ]
    manifest = {
        "schema": "market-aligner.private-input-recovery.v1",
        "approval_id": _APPROVAL,
        "destination": str(approved_dir),
        "files": descriptors,
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    manifest_path = approved_dir / "recovery-manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o600)
    return store, manifest_bytes, profile_bytes, evidence_bytes, str(manifest_path.relative_to(data_home))


def _response() -> dict[str, Any]:
    return {
        "selection": [
            {
                "evidence_id": evidence_id,
                "proof_class": "work_artifact",
                "document_targets": ["cv", "cover_letter"],
            }
            for evidence_id in ("ev-current", "ev-other")
        ],
        "excluded_ids": ["ev-correction", "ev-old"],
        "correction_assessments": [
            {
                "source_evidence_id": "ev-correction",
                "relationship": "corrects",
                "affected_evidence_ids": ["ev-old"],
            }
        ],
    }


def test_activation_binds_manifest_current_snapshot_selection_and_exact_spans(
    tmp_path: Path,
) -> None:
    store, manifest_bytes, profile_bytes, evidence_bytes, relative_manifest = _fixture(tmp_path)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex executable")
    runner = ActivationRunner(_response())
    gateway = CodexSemanticGateway(
        model="synthetic-model",
        codex_binary=str(binary),
        environment={"HOME": str(tmp_path), "PATH": "/usr/bin"},
        runner=runner,
    )
    with PinnedRecoveryInputs(
        data_home=store.paths.root,
        manifest_relative_path=relative_manifest,
        expected_manifest_sha256=manifest_sha256,
        approval_id=_APPROVAL,
    ) as recovered:
        snapshot = store.coherent_snapshot(_PROFILE_ID, require_committed_generation=True)
        try:
            document = compile_current_profile_activation(
                profile_id=_PROFILE_ID,
                manifest_bytes=recovered.manifest_bytes,
                expected_manifest_sha256=manifest_sha256,
                approval_id=_APPROVAL,
                recovered_profile_bytes=recovered.files[
                    "candidate_profile_and_job_preferences"
                ],
                recovered_evidence_bytes=recovered.files[
                    "existing_profile_claims_and_provenance"
                ],
                snapshot=snapshot,
                gateway=gateway,
            )
            recovered.revalidate()
        finally:
            snapshot.close()

    packet = document["factual_packet"]
    assert [row["id"] for row in packet["statements"]] == ["ev-current", "ev-other"]
    assert "Synthetic old claim" not in json.dumps(packet)
    assert document["selection"]["correction_assessments"][0]["affected_evidence_ids"] == [
        "ev-old"
    ]
    evidence_lines = evidence_bytes.splitlines(keepends=True)
    old_line_index = next(
        index
        for index, line in enumerate(evidence_lines)
        if json.loads(line)["evidence_id"] == "ev-old"
    )
    assert document["source_spans"]["ev-old"]["start_byte"] == sum(
        len(line) for line in evidence_lines[:old_line_index]
    )
    assert document["source_hashes"]["profile"] == hashlib.sha256(profile_bytes).hexdigest()
    packet_bytes = (
        json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    assert document["factual_packet_sha256"] == hashlib.sha256(packet_bytes).hexdigest()
    assert document["application_authority"] is False
    assert document["release_authority"] is False
    assert document["submission_authority"] is False
    assert document["provider_receipt"]["transport"]["invocation_count"] == 1
    assert runner.calls == 1


def test_activation_selection_receives_profile_exclusions_and_preserves_other_facts(
    tmp_path: Path,
) -> None:
    store, manifest_bytes, profile_bytes, evidence_bytes, relative_manifest = _fixture(
        tmp_path,
        constraints={"evidence_scope": "synthetic coursework only"},
        blind_spots=("No synthetic employment history is verified.",),
        unknowns=("Use outside coursework is unknown.",),
        exclusions=("Do not use the sample-dataset project as candidate experience.",),
    )
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex executable")
    runner = ContextAwareActivationRunner()
    gateway = CodexSemanticGateway(
        model="synthetic-model",
        codex_binary=str(binary),
        environment={"HOME": str(tmp_path), "PATH": "/usr/bin"},
        runner=runner,
    )
    with PinnedRecoveryInputs(
        data_home=store.paths.root,
        manifest_relative_path=relative_manifest,
        expected_manifest_sha256=manifest_sha256,
        approval_id=_APPROVAL,
    ) as recovered:
        snapshot = store.coherent_snapshot(_PROFILE_ID, require_committed_generation=True)
        try:
            document = compile_current_profile_activation(
                profile_id=_PROFILE_ID,
                manifest_bytes=recovered.manifest_bytes,
                expected_manifest_sha256=manifest_sha256,
                approval_id=_APPROVAL,
                recovered_profile_bytes=recovered.files[
                    "candidate_profile_and_job_preferences"
                ],
                recovered_evidence_bytes=recovered.files[
                    "existing_profile_claims_and_provenance"
                ],
                snapshot=snapshot,
                gateway=gateway,
            )
            recovered.revalidate()
        finally:
            snapshot.close()

    assert runner.calls == 1
    assert runner.profile_context["active_profile_sha256"] == document[
        "active_snapshot_hashes"
    ]["profile_sha256"]
    assert document["profile_selection_context_sha256"] == runner.profile_context_sha256
    assert [row["id"] for row in document["factual_packet"]["statements"]] == [
        "ev-other"
    ]
    assert document["selection"]["excluded_ids"] == [
        "ev-correction",
        "ev-current",
        "ev-old",
    ]
    assert document["selection"]["correction_assessments"][0][
        "affected_evidence_ids"
    ] == ["ev-old"]
    assert document["application_authority"] is False
    assert document["release_authority"] is False
    assert document["submission_authority"] is False


def test_activation_refuses_recovered_bytes_that_do_not_match_manifest_before_provider(
    tmp_path: Path,
) -> None:
    store, manifest_bytes, profile_bytes, evidence_bytes, relative_manifest = _fixture(tmp_path)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex executable")
    runner = ActivationRunner(_response())
    gateway = CodexSemanticGateway(
        model="synthetic-model",
        codex_binary=str(binary),
        environment={"HOME": str(tmp_path), "PATH": "/usr/bin"},
        runner=runner,
    )
    with PinnedRecoveryInputs(
        data_home=store.paths.root,
        manifest_relative_path=relative_manifest,
        expected_manifest_sha256=manifest_sha256,
        approval_id=_APPROVAL,
    ) as recovered:
        snapshot = store.coherent_snapshot(_PROFILE_ID, require_committed_generation=True)
        try:
            with pytest.raises(ValueError, match="^current_profile_activation_invalid$"):
                compile_current_profile_activation(
                    profile_id=_PROFILE_ID,
                    manifest_bytes=recovered.manifest_bytes,
                    expected_manifest_sha256=manifest_sha256,
                    approval_id=_APPROVAL,
                    recovered_profile_bytes=profile_bytes + b"\n",
                    recovered_evidence_bytes=evidence_bytes,
                    snapshot=snapshot,
                    gateway=gateway,
                )
        finally:
            snapshot.close()
    assert runner.calls == 0


def test_activation_artifact_is_private_create_only_and_hash_bound(tmp_path: Path) -> None:
    store, _manifest, _profile, _evidence, _relative = _fixture(tmp_path)
    document: dict[str, Any] = {
        "schema_version": "market-aligner.current-profile-fact-activation.v1",
        "profile_id": _PROFILE_ID,
        "application_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    document["activation_sha256"] = canonical_hash(document)
    path, digest = write_current_activation_artifact(
        data_home=store.paths.root, profile_id=_PROFILE_ID, document=document
    )
    written = path.read_bytes()
    assert hashlib.sha256(written).hexdigest() == digest
    assert json.loads(written) == document
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.getuid()


def test_project_current_activation_cli_revalidates_and_emits_private_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store, manifest_bytes, profile_bytes, evidence_bytes, relative_manifest = _fixture(
        tmp_path
    )
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex executable")
    runner = ActivationRunner(_response())
    gateway = CodexSemanticGateway(
        model="synthetic-model",
        codex_binary=str(binary),
        environment={"HOME": str(tmp_path), "PATH": "/usr/bin"},
        runner=runner,
    )
    with PinnedRecoveryInputs(
        data_home=store.paths.root,
        manifest_relative_path=relative_manifest,
        expected_manifest_sha256=manifest_sha256,
        approval_id=_APPROVAL,
    ) as recovered:
        snapshot = store.coherent_snapshot(
            _PROFILE_ID, require_committed_generation=True
        )
        try:
            activation_document = compile_current_profile_activation(
                profile_id=_PROFILE_ID,
                manifest_bytes=recovered.manifest_bytes,
                expected_manifest_sha256=manifest_sha256,
                approval_id=_APPROVAL,
                recovered_profile_bytes=profile_bytes,
                recovered_evidence_bytes=evidence_bytes,
                snapshot=snapshot,
                gateway=gateway,
            )
            active_hashes = dict(snapshot.hashes)
        finally:
            snapshot.close()
    activation_path, activation_file_sha256 = write_current_activation_artifact(
        data_home=store.paths.root,
        profile_id=_PROFILE_ID,
        document=activation_document,
    )
    projection_namespace = store.paths.outputs / "current-profile-projections"
    assert not projection_namespace.exists()

    from market_aligner.cli import build_parser

    arguments = build_parser().parse_args(
        [
            "profiles",
            "project-current-activation",
            "--profile-id",
            _PROFILE_ID,
            "--activation-name",
            activation_path.name,
            "--activation-file-sha256",
            activation_file_sha256,
            "--manifest-relative-path",
            relative_manifest,
            "--manifest-sha256",
            manifest_sha256,
            "--approval-id",
            _APPROVAL,
            "--data-home",
            str(store.paths.root),
        ]
    )
    assert arguments.handler(arguments) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "projected_non_authoritative"
    assert output["activation_file_sha256"] == activation_file_sha256
    assert output["activation_sha256"] == activation_document["activation_sha256"]
    assert output["new_provider_invocations"] == 0
    assert output["application_authority"] is False
    assert output["release_authority"] is False
    assert output["submission_authority"] is False
    assert runner.calls == 1

    document_paths = {
        key: Path(value["path"])
        for key, value in output["documents"].items()
    }
    assert set(document_paths) == {
        "evidence_packet_bytes",
        "candidate_projection_bytes",
        "candidate_authority_bytes",
        "profile_projection_receipt_bytes",
    }
    assert len({path.parent for path in document_paths.values()}) == 1
    assert {path.parent for path in document_paths.values()} == {activation_path.parent}
    for key, path in document_paths.items():
        assert path.name.startswith("projection-")
        assert hashlib.sha256(path.read_bytes()).hexdigest() == output["documents"][key][
            "sha256"
        ]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.getuid()
    assert not projection_namespace.exists()
    assert stat.S_IMODE(activation_path.parent.stat().st_mode) == 0o700
    packet = json.loads(document_paths["evidence_packet_bytes"].read_bytes())
    authority = json.loads(document_paths["candidate_authority_bytes"].read_bytes())
    receipt = json.loads(
        document_paths["profile_projection_receipt_bytes"].read_bytes()
    )
    assert packet["statements"] == activation_document["factual_packet"]["statements"]
    assert authority["profile_binding"] == {
        "profile_id": _PROFILE_ID,
        "profile_sha256": active_hashes["profile_sha256"],
        "evidence_ledger_sha256": active_hashes["evidence_ledger_sha256"],
    }
    assert receipt["authority_sha256"] == output["documents"][
        "candidate_authority_bytes"
    ]["sha256"]
