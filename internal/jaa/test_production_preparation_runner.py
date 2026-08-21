from __future__ import annotations

import hashlib
import inspect
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation import production_preparation_runner as runner
from career_automation.market_aligner_preparation import MarketApplicationPreparation


def _deployment(tmp_path: Path) -> runner._ProductionPreparationDeployment:
    binary = tmp_path / "codex"
    binary.write_bytes(b"fixture executable")
    binary.chmod(0o700)
    return runner._ProductionPreparationDeployment(
        repository_root=tmp_path / "repository",
        admission_database=tmp_path / "admissions.sqlite3",
        outbox_root=tmp_path / "outbox",
        candidate_authority_path=tmp_path / "candidate.json",
        contact_authority_path=tmp_path / "contact.json",
        contact_public_key_path=tmp_path / "public.pem",
        contact_registry_path=tmp_path / "registry.json",
        output_root=tmp_path / "preparations",
        recruiter_archive_root=tmp_path / "recruiter",
        codex_binary=binary,
        model="gpt-test",
        timeout_seconds=30,
    )


def test_public_runner_accepts_only_application_id() -> None:
    assert tuple(inspect.signature(runner.run_production_preparation).parameters) == (
        "application_id",
    )


def test_fixed_runner_wires_cv_cover_and_recruiter_without_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    application_id = "app_" + "1" * 64
    captured: dict[str, object] = {}
    adapter_arguments: dict[str, object] = {}
    stages: list[str] = []
    monkeypatch.delenv(runner.PUBLIC_KEY_ENV, raising=False)
    monkeypatch.delenv(runner.REGISTRY_ENV, raising=False)
    monkeypatch.delenv("JAA_POPPLER_BIN", raising=False)

    monkeypatch.setattr(runner, "_git_commit", lambda path, **kwargs: "2" * 40)
    monkeypatch.setattr(runner, "_source_record_for_application", lambda *args: "3" * 64)
    def protected_outbox(*args, **kwargs):
        adapter_arguments.update(kwargs)
        return object()

    monkeypatch.setattr(runner, "ProtectedLocalOutbox", protected_outbox)
    monkeypatch.setattr(runner, "HandoffAdmissionStore", lambda *args, **kwargs: object())
    monkeypatch.setattr(runner, "installed_production_current_time_witness", lambda: object())
    monkeypatch.setattr(
        runner,
        "PRODUCTION_POPPLER_BIN",
        tmp_path,
    )
    hashes = {}
    for name in runner.PRODUCTION_POPPLER_SHA256:
        path = tmp_path / name
        path.write_bytes(name.encode())
        hashes[name] = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_SHA256", hashes)
    authority_constants = (
        (deployment.candidate_authority_path, "PRODUCTION_CANDIDATE_AUTHORITY_SHA256"),
        (deployment.contact_authority_path, "PRODUCTION_CONTACT_ENVELOPE_SHA256"),
        (deployment.contact_public_key_path, "PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256"),
        (deployment.contact_registry_path, "PRODUCTION_CONTACT_REGISTRY_FILE_SHA256"),
    )
    import hashlib
    for path, name in authority_constants:
        path.write_bytes(name.encode())
        monkeypatch.setattr(runner, name, hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(
        runner,
        "_expected_configuration",
        lambda: {"codex_binary_sha256": hashlib.sha256(deployment.codex_binary.read_bytes()).hexdigest()},
    )

    class _Resources:
        def pin_file(self, *args, **kwargs): return args[0]
        def pin_private_directory(self, path): return path
        def verify(self): pass
        def close(self): pass

    monkeypatch.setattr(runner, "_PinnedPreparationResources", _Resources)

    class _Pinned:
        repository_descriptor = 10
        data_descriptor = 9
        def __init__(self, deployment): pass
        def open_bundle(self, source): return 11
        def register_adapter(self, adapter): pass
        def verify_references(self): pass
        def close(self): pass

    monkeypatch.setattr(runner, "_PinnedProductionPaths", _Pinned)
    def open_admission(_parent):
        return (
            os.open(tmp_path, os.O_RDONLY),
            os.open(deployment.codex_binary, os.O_RDONLY),
        )

    monkeypatch.setattr(
        runner,
        "_open_admission_database",
        open_admission,
    )

    class _Adapter:
        provider = "fixture"
        model = "gpt-test"
        transport_identity = "4" * 64
        environment = "production"

        def __init__(self, *, stage: str, **kwargs):
            self.stage = stage
            stages.append(stage)

    monkeypatch.setattr(runner, "DetachedCodexEditorialAdapter", _Adapter)
    assessor = object()
    monkeypatch.setattr(runner, "ProductionDetachedRecruiterAssessor", lambda **kwargs: assessor)
    preparation_id = "5" * 64
    destination = deployment.output_root / "preparations" / preparation_id
    expected = MarketApplicationPreparation(
        preparation_id=preparation_id,
        path=destination,
        receipt_sha256=hashlib.sha256(b"receipt").hexdigest(),
        orchestration_sha256="7" * 64,
    )

    def prepare(**kwargs):
        captured.update(kwargs)
        objects = destination / "objects"
        objects.mkdir(parents=True, mode=0o700, exist_ok=True)
        deployment.output_root.chmod(0o700)
        destination.parent.chmod(0o700)
        destination.chmod(0o700)
        objects.chmod(0o700)
        for path, value in (
            (objects / ("a" * 64), b"authority"),
            (destination / "cv.pdf", b"cv"),
            (destination / "cover-letter.pdf", b"letter"),
            (destination / "receipt.json", b"receipt"),
        ):
            if not path.exists():
                path.write_bytes(value)
                path.chmod(0o600)
        return expected

    monkeypatch.setattr(runner, "prepare_admitted_market_application_from_authorities", prepare)
    result = runner._run_production_preparation(application_id, deployment)
    assert result == expected
    assert stages == [
        "resume_writer", "humanizer", "cover_letter_writer", "cover_letter_humanizer"
    ]
    assert captured["environment"] == "production"
    assert captured["editorial_runtime"].document_kind == "cv"
    assert captured["cover_letter_editorial_runtime"].document_kind == "cover_letter"
    assert captured["editorial_runtime"] is not captured["cover_letter_editorial_runtime"]
    assert adapter_arguments["expected_source_record_sha256"] == "3" * 64
    assert adapter_arguments["allowed_producer_commits"] == frozenset({"2" * 40})
    assert captured["orchestration_extras"]["production_recruiter_assessor"] is assessor
    assert result.release_authority is False
    assert runner.PUBLIC_KEY_ENV not in __import__("os").environ
    assert runner.REGISTRY_ENV not in __import__("os").environ
    assert "JAA_POPPLER_BIN" not in __import__("os").environ

    os.environ[runner.PUBLIC_KEY_ENV] = "prior-public-key"
    os.environ[runner.REGISTRY_ENV] = "prior-registry"
    os.environ["JAA_POPPLER_BIN"] = "prior-poppler"

    def fail_preparation(**kwargs):
        raise RuntimeError("injected preparation failure")

    monkeypatch.setattr(
        runner,
        "prepare_admitted_market_application_from_authorities",
        fail_preparation,
    )
    with pytest.raises(RuntimeError, match="injected preparation failure"):
        runner._run_production_preparation(application_id, deployment)
    assert os.environ[runner.PUBLIC_KEY_ENV] == "prior-public-key"
    assert os.environ[runner.REGISTRY_ENV] == "prior-registry"
    assert os.environ["JAA_POPPLER_BIN"] == "prior-poppler"


@pytest.mark.parametrize("application_id", ("bad", "app_" + "z" * 64))
def test_fixed_runner_rejects_malformed_application_before_transport(
    tmp_path: Path,
    application_id: str,
) -> None:
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="application ID"):
        runner._run_production_preparation(application_id, _deployment(tmp_path))


def test_poppler_substitution_rejects_before_provider_availability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    calls = {"adapter": 0, "recruiter": 0}
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_BIN", tmp_path)
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_SHA256", {"pdfinfo": "0" * 64})
    (tmp_path / "pdfinfo").write_bytes(b"substituted")
    monkeypatch.setattr(
        runner,
        "DetachedCodexEditorialAdapter",
        lambda **kwargs: calls.__setitem__("adapter", calls["adapter"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "ProductionDetachedRecruiterAssessor",
        lambda **kwargs: calls.__setitem__("recruiter", calls["recruiter"] + 1),
    )
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="Poppler"):
        runner._run_production_preparation("app_" + "1" * 64, deployment)
    assert calls == {"adapter": 0, "recruiter": 0}


def test_pinned_file_rejects_hash_mode_link_and_symlink_substitution(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority.json"
    path.write_bytes(b"authority")
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    path.chmod(0o644)
    resources = runner._PinnedPreparationResources()
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="identity"):
        resources.pin_file(
            path,
            expected_sha256=digest,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
        )
    resources.close()

    path.chmod(0o600)
    hardlink = tmp_path / "authority-hardlink.json"
    os.link(path, hardlink)
    resources = runner._PinnedPreparationResources()
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="identity"):
        resources.pin_file(
            path,
            expected_sha256=digest,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
        )
    resources.close()
    hardlink.unlink()

    target = tmp_path / "target.json"
    path.rename(target)
    path.symlink_to(target)
    resources = runner._PinnedPreparationResources()
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="unavailable"):
        resources.pin_file(
            path,
            expected_sha256=digest,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
        )
    resources.close()


def test_pinned_file_detects_leaf_and_ancestor_replacement(tmp_path: Path) -> None:
    parent = tmp_path / "authority-root"
    parent.mkdir(mode=0o700)
    path = parent / "authority.json"
    path.write_bytes(b"authority")
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    resources = runner._PinnedPreparationResources()
    resources.pin_file(
        path,
        expected_sha256=digest,
        expected_mode=0o600,
        expected_uid=os.geteuid(),
    )
    path.unlink()
    path.write_bytes(b"authority")
    path.chmod(0o600)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="changed"):
        resources.verify()
    resources.close()

    path.unlink()
    path.write_bytes(b"authority")
    path.chmod(0o600)
    resources = runner._PinnedPreparationResources()
    resources.pin_file(
        path,
        expected_sha256=digest,
        expected_mode=0o600,
        expected_uid=os.geteuid(),
    )
    moved = tmp_path / "authority-root-old"
    parent.rename(moved)
    parent.mkdir(mode=0o700)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="directory changed"):
        resources.verify()
    resources.close()


def test_pinned_output_directory_detects_reference_replacement(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    output = state / "preparations"
    resources = runner._PinnedPreparationResources()
    resources.pin_private_directory(output)
    moved = state / "preparations-old"
    output.rename(moved)
    output.mkdir(mode=0o700)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="directory changed"):
        resources.verify()
    resources.close()


def test_preparation_output_requires_exact_private_replay(tmp_path: Path) -> None:
    preparation_id = "5" * 64
    output_root = tmp_path / "output"
    destination = output_root / "preparations" / preparation_id
    objects = destination / "objects"
    objects.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    (output_root / "preparations").chmod(0o700)
    destination.chmod(0o700)
    objects.chmod(0o700)
    for path, value in (
        (objects / ("a" * 64), b"authority"),
        (destination / "cv.pdf", b"cv"),
        (destination / "cover-letter.pdf", b"letter"),
        (destination / "receipt.json", b"receipt"),
    ):
        path.write_bytes(value)
        path.chmod(0o600)
    result = MarketApplicationPreparation(
        preparation_id=preparation_id,
        path=destination,
        receipt_sha256=hashlib.sha256(b"receipt").hexdigest(),
        orchestration_sha256="7" * 64,
    )
    runner._verify_preparation_output(result, output_root)

    hardlink = tmp_path / "cv-hardlink"
    os.link(destination / "cv.pdf", hardlink)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="output file"):
        runner._verify_preparation_output(result, output_root)
    hardlink.unlink()

    (destination / "receipt.json").write_bytes(b"substituted")
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="receipt differs"):
        runner._verify_preparation_output(result, output_root)
