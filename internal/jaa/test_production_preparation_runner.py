from __future__ import annotations

import hashlib
import inspect
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

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


def _write_admission_fixture(
    database: Path,
    application_id: str,
    *,
    context_producer: str,
    stored_producer: str | None = None,
    canonical: bool = True,
    context_sha256: str | None = None,
) -> None:
    handoff_root = "4" * 64
    context = {
        "environment": "production",
        "handoff_root_sha256": handoff_root,
        "producer_commit_sha": context_producer,
        "producer_product": "market-aligner",
        "source_record_sha256": "3" * 64,
        "trust_root_id": runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }
    if canonical:
        context_bytes = runner.canonical_json_bytes(context)
    else:
        context_bytes = json.dumps(context, indent=2, sort_keys=True).encode() + b"\n"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE application_admissions ("
        "application_id TEXT PRIMARY KEY, admission_context_bytes BLOB NOT NULL, "
        "admission_context_sha256 TEXT NOT NULL, producer_commit_sha TEXT NOT NULL, "
        "producer_product TEXT NOT NULL, environment TEXT NOT NULL, "
        "trust_root_id TEXT NOT NULL, handoff_root_sha256 TEXT NOT NULL, "
        "sealed INTEGER NOT NULL)"
    )
    connection.execute(
        "INSERT INTO application_admissions VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (
            application_id,
            context_bytes,
            context_sha256 or hashlib.sha256(context_bytes).hexdigest(),
            stored_producer or context_producer,
            "market-aligner",
            "production",
            runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
            handoff_root,
        ),
    )
    connection.commit()
    connection.close()


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _real_preflight_deployment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[runner._ProductionPreparationDeployment, dict[str, Path]]:
    data_home = tmp_path / "data-home"
    admission_root = data_home / "state" / "jaa-production-admissions"
    admission_root.mkdir(parents=True, mode=0o700)
    (data_home / "state").chmod(0o700)
    admission_root.chmod(0o700)
    database = admission_root / "admissions.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE fixture (identity TEXT NOT NULL)")
    connection.commit()
    connection.close()
    database.chmod(0o600)

    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    outbox = tmp_path / "outbox"
    outbox.mkdir(mode=0o700)
    poppler = tmp_path / "poppler"
    poppler.mkdir(mode=0o700)
    poppler_libraries = tmp_path / "poppler-libraries"
    poppler_libraries.mkdir(mode=0o700)
    codex = tmp_path / "codex"
    codex.write_bytes(b"exact codex")
    codex.chmod(0o755)
    paths = {
        "candidate": tmp_path / "authority" / "candidate.json",
        "contact": tmp_path / "contact" / "contact.json",
        "public_key": tmp_path / "contact" / "public.pem",
        "registry": tmp_path / "contact" / "registry.json",
        "codex": codex,
        "database": database,
        "output": tmp_path / "output",
        "recruiter": tmp_path / "recruiter",
    }
    paths["candidate"].parent.mkdir(mode=0o700)
    paths["contact"].parent.mkdir(mode=0o700)
    for name in ("candidate", "contact", "public_key", "registry"):
        value = (
            b'{"prior_registry_sha256":null}'
            if name == "registry"
            else name.encode()
        )
        paths[name].write_bytes(value)
        paths[name].chmod(0o600)
    poppler_hashes: dict[str, str] = {}
    for name in runner.PRODUCTION_POPPLER_SHA256:
        path = poppler / name
        path.write_bytes(name.encode())
        path.chmod(0o755)
        poppler_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    poppler_library_hashes: dict[str, str] = {}
    for name in runner.PRODUCTION_POPPLER_LIBRARY_SHA256:
        path = poppler_libraries / name
        path.write_bytes(name.encode())
        path.chmod(0o644)
        poppler_library_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    paths["poppler"] = poppler / "pdfinfo"

    deployment = runner._ProductionPreparationDeployment(
        repository_root=repository,
        admission_database=database,
        outbox_root=outbox,
        candidate_authority_path=paths["candidate"],
        contact_authority_path=paths["contact"],
        contact_public_key_path=paths["public_key"],
        contact_registry_path=paths["registry"],
        output_root=paths["output"],
        recruiter_archive_root=paths["recruiter"],
        codex_binary=codex,
        model="gpt-test",
        timeout_seconds=30,
    )
    monkeypatch.setattr(runner, "PRODUCTION_MARKET_DATA_HOME", data_home)
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_BIN", poppler)
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_SHA256", poppler_hashes)
    monkeypatch.setattr(
        runner, "PRODUCTION_POPPLER_LIBRARY_DIRECTORY", poppler_libraries
    )
    monkeypatch.setattr(
        runner, "PRODUCTION_POPPLER_LIBRARY_SHA256", poppler_library_hashes
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CODEX_BINARY_SHA256",
        hashlib.sha256(codex.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(runner, "PRODUCTION_CODEX_OWNER_UID", os.geteuid())
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CANDIDATE_AUTHORITY_SHA256",
        hashlib.sha256(paths["candidate"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CONTACT_ENVELOPE_SHA256",
        hashlib.sha256(paths["contact"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256",
        hashlib.sha256(paths["public_key"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CONTACT_REGISTRY_FILE_SHA256",
        hashlib.sha256(paths["registry"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(runner, "_git_commit", lambda *args, **kwargs: "2" * 40)

    class _Pinned:
        def __init__(self, _deployment):
            self.data_descriptor = os.open(data_home, os.O_RDONLY | os.O_DIRECTORY)
            self.repository_descriptor = os.open(
                repository, os.O_RDONLY | os.O_DIRECTORY
            )
            self.bundle_descriptor: int | None = None

        def open_bundle(self, _source):
            self.bundle_descriptor = os.open(outbox, os.O_RDONLY | os.O_DIRECTORY)
            return self.bundle_descriptor

        def register_adapter(self, _adapter):
            pass

        def verify_references(self):
            pass

        def close(self):
            if self.bundle_descriptor is not None:
                os.close(self.bundle_descriptor)
            os.close(self.repository_descriptor)
            os.close(self.data_descriptor)

    monkeypatch.setattr(runner, "_PinnedProductionPaths", _Pinned)
    monkeypatch.setattr(
        runner,
        "_source_record_for_application",
        lambda *args: runner._AdmittedSourceRecord("3" * 64, "2" * 40),
    )
    monkeypatch.setattr(runner, "ProtectedLocalOutbox", lambda *args, **kwargs: object())
    monkeypatch.setattr(runner, "HandoffAdmissionStore", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        runner, "installed_production_current_time_witness", lambda: object()
    )
    return deployment, paths


def test_public_runner_accepts_only_application_id() -> None:
    assert tuple(inspect.signature(runner.run_production_preparation).parameters) == (
        "application_id",
    )


def test_registry_chain_predecessors_remain_in_the_resource_lease(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    prior_identity = "1" * 64
    head = registry / ("2" * 64 + ".json")
    prior = registry / f"{prior_identity}.json"
    head.write_bytes(
        json.dumps(
            {"prior_registry_sha256": prior_identity},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    prior.write_bytes(b'{"prior_registry_sha256":null}')
    head.chmod(0o600)
    prior.chmod(0o600)
    resources = runner._PinnedPreparationResources()
    try:
        resources.pin_file(
            head,
            expected_sha256=hashlib.sha256(head.read_bytes()).hexdigest(),
            expected_mode=0o600,
            expected_uid=os.geteuid(),
            label="contact registry",
        )
        chain = resources.pin_contact_registry_chain(head)
        assert tuple(path for path, _value in chain) == (head, prior)
        assert tuple(value for _path, value in chain) == (
            head.read_bytes(),
            prior.read_bytes(),
        )

        replacement = registry / "replacement.json"
        replacement.write_bytes(prior.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(prior)
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="changed during operation",
        ):
            resources.verify()
    finally:
        resources.close()


def test_source_record_binds_exact_sealed_producer_context(tmp_path: Path) -> None:
    application_id = "app_" + "1" * 64
    database = tmp_path / "admissions.sqlite3"
    _write_admission_fixture(
        database,
        application_id,
        context_producer="2" * 40,
    )
    admitted = runner._source_record_for_application(database, application_id)
    assert admitted == runner._AdmittedSourceRecord("3" * 64, "2" * 40)


@pytest.mark.parametrize(
    "substitution",
    ("stored-producer", "context-encoding", "context-hash"),
)
def test_source_record_rejects_sealed_context_substitution(
    tmp_path: Path, substitution: str
) -> None:
    application_id = "app_" + "1" * 64
    database = tmp_path / "admissions.sqlite3"
    _write_admission_fixture(
        database,
        application_id,
        context_producer="2" * 40,
        stored_producer="1" * 40 if substitution == "stored-producer" else None,
        canonical=substitution != "context-encoding",
        context_sha256="0" * 64 if substitution == "context-hash" else None,
    )
    with pytest.raises(
        runner.ProductionPreparationDeploymentError,
        match="sealed admission context differs",
    ):
        runner._source_record_for_application(database, application_id)


def test_admitted_ancestor_with_unchanged_handoff_authority_is_compatible(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Artiom Gutu")
    _git(repository, "config", "user.email", "gutu.artiom444@gmail.com")
    authority = repository / runner._HANDOFF_AUTHORITY_PATHS[0]
    authority.parent.mkdir(parents=True)
    authority.write_text("sealed authority\n")
    _git(repository, "add", str(authority.relative_to(repository)))
    _git(repository, "commit", "-qm", "admitted")
    admitted = _git(repository, "rev-parse", "HEAD")
    (repository / "unrelated.txt").write_text("current runtime\n")
    _git(repository, "add", "unrelated.txt")
    _git(repository, "commit", "-qm", "runtime-only change")
    current = _git(repository, "rev-parse", "HEAD")
    descriptor = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
    try:
        runner._require_compatible_admitted_producer(
            repository_descriptor=descriptor,
            admitted_producer_commit=admitted,
            current_commit=current,
        )
    finally:
        os.close(descriptor)


def test_admitted_producer_rejects_authority_change_and_nonancestor(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Artiom Gutu")
    _git(repository, "config", "user.email", "gutu.artiom444@gmail.com")
    authority = repository / runner._HANDOFF_AUTHORITY_PATHS[0]
    authority.parent.mkdir(parents=True)
    authority.write_text("sealed authority\n")
    _git(repository, "add", str(authority.relative_to(repository)))
    _git(repository, "commit", "-qm", "admitted")
    admitted = _git(repository, "rev-parse", "HEAD")
    authority.write_text("changed authority\n")
    _git(repository, "add", str(authority.relative_to(repository)))
    _git(repository, "commit", "-qm", "changed authority")
    changed = _git(repository, "rev-parse", "HEAD")
    descriptor = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="handoff authority changed",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=admitted,
                current_commit=changed,
            )
        empty_tree = _git(repository, "hash-object", "-t", "tree", "/dev/null")
        diverged = _git(repository, "commit-tree", empty_tree, "-m", "diverged")
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="not an ancestor",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=diverged,
                current_commit=changed,
            )
    finally:
        os.close(descriptor)


def test_fixed_runner_wires_cv_cover_and_recruiter_without_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    application_id = "app_" + "1" * 64
    captured: dict[str, object] = {}
    adapter_arguments: dict[str, object] = {}
    editorial_arguments: list[dict[str, object]] = []
    recruiter_arguments: dict[str, object] = {}
    poppler_arguments: dict[str, object] = {}
    producer_compatibility: dict[str, object] = {}
    stages: list[str] = []
    monkeypatch.delenv(runner.PUBLIC_KEY_ENV, raising=False)
    monkeypatch.delenv(runner.REGISTRY_ENV, raising=False)
    monkeypatch.delenv("JAA_POPPLER_BIN", raising=False)

    monkeypatch.setattr(runner, "_git_commit", lambda path, **kwargs: "2" * 40)
    monkeypatch.setattr(
        runner,
        "_source_record_for_application",
        lambda *args: runner._AdmittedSourceRecord("3" * 64, "1" * 40),
    )
    monkeypatch.setattr(
        runner,
        "_require_compatible_admitted_producer",
        lambda **kwargs: producer_compatibility.update(kwargs),
    )
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
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_LIBRARY_DIRECTORY", tmp_path)
    library_hashes = {}
    for name in runner.PRODUCTION_POPPLER_LIBRARY_SHA256:
        path = tmp_path / name
        path.write_bytes(name.encode())
        library_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        runner, "PRODUCTION_POPPLER_LIBRARY_SHA256", library_hashes
    )
    authority_constants = (
        (deployment.candidate_authority_path, "PRODUCTION_CANDIDATE_AUTHORITY_SHA256"),
        (deployment.contact_authority_path, "PRODUCTION_CONTACT_ENVELOPE_SHA256"),
        (deployment.contact_public_key_path, "PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256"),
        (deployment.contact_registry_path, "PRODUCTION_CONTACT_REGISTRY_FILE_SHA256"),
    )
    for path, name in authority_constants:
        path.write_bytes(name.encode())
        monkeypatch.setattr(runner, name, hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(
        runner,
        "_expected_configuration",
        lambda: {"codex_binary_sha256": hashlib.sha256(deployment.codex_binary.read_bytes()).hexdigest()},
    )

    descriptor_holder: dict[str, int] = {}

    class _Resources:
        def __init__(self):
            self.directory_descriptors: list[int] = []
        def pin_file(self, *args, **kwargs): return args[0]
        def pin_private_directory(self, path):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            return path
        def file_bytes(self, path): return path.read_bytes()
        def file_descriptor(self, path):
            return (
                descriptor_holder["database"]
                if path == deployment.admission_database
                else 44
            )
        def pin_contact_registry_chain(self, path):
            return ((path, path.read_bytes()),)
        def directory_descriptor(self, path):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            self.directory_descriptors.append(descriptor)
            return descriptor
        def verify(self): pass
        def close(self):
            while self.directory_descriptors:
                os.close(self.directory_descriptors.pop())

    monkeypatch.setattr(runner, "_PinnedPreparationResources", _Resources)
    pinned_poppler = object()
    def pin_poppler(
        descriptors,
        hashes,
        *,
        library_descriptors,
        expected_library_sha256,
    ):
        poppler_arguments.update(
            {
                "descriptors": descriptors,
                "hashes": hashes,
                "library_descriptors": library_descriptors,
                "library_hashes": expected_library_sha256,
            }
        )
        return pinned_poppler

    monkeypatch.setattr(runner, "pinned_poppler_runtime", pin_poppler)

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
        database = os.open(deployment.codex_binary, os.O_RDONLY)
        descriptor_holder["database"] = database
        return (os.open(tmp_path, os.O_RDONLY), database)

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
            editorial_arguments.append(dict(kwargs))

    monkeypatch.setattr(runner, "DetachedCodexEditorialAdapter", _Adapter)
    assessor = object()
    def production_assessor(**kwargs):
        recruiter_arguments.update(kwargs)
        return assessor

    monkeypatch.setattr(runner, "ProductionDetachedRecruiterAssessor", production_assessor)
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
    assert adapter_arguments["allowed_producer_commits"] == frozenset({"1" * 40})
    assert producer_compatibility["admitted_producer_commit"] == "1" * 40
    assert producer_compatibility["current_commit"] == "2" * 40
    assert captured["orchestration_extras"]["production_recruiter_assessor"] is assessor
    assert captured["orchestration_extras"]["poppler_runtime"] is pinned_poppler
    assert {row["codex_binary_fd"] for row in editorial_arguments} == {44}
    assert recruiter_arguments["codex_binary_fd"] == 44
    assert isinstance(recruiter_arguments["archive_descriptor"], int)
    assert set(poppler_arguments["descriptors"]) == set(
        runner.PRODUCTION_POPPLER_SHA256
    )
    assert set(poppler_arguments["library_descriptors"]) == set(
        runner.PRODUCTION_POPPLER_LIBRARY_SHA256
    )
    assert poppler_arguments["library_hashes"] == (
        runner.PRODUCTION_POPPLER_LIBRARY_SHA256
    )
    assert captured["candidate_authority_bytes"] == (
        deployment.candidate_authority_path.read_bytes()
    )
    assert captured["contact_resource_lease"].authority_bytes == (
        deployment.contact_authority_path.read_bytes()
    )
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


@pytest.mark.parametrize(
    ("resource_name", "stage"),
    (
        ("database", "database"),
        ("candidate", "resources"),
        ("contact", "resources"),
        ("public_key", "resources"),
        ("registry", "resources"),
        ("codex", "resources"),
        ("poppler", "resources"),
        ("output", "resources"),
        ("recruiter", "resources"),
    ),
)
def test_after_preflight_resource_replacement_fails_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    resource_name: str,
    stage: str,
) -> None:
    deployment, paths = _real_preflight_deployment(monkeypatch, tmp_path)
    calls = {"editorial": 0, "recruiter": 0, "preparation": 0}
    monkeypatch.setattr(
        runner,
        "DetachedCodexEditorialAdapter",
        lambda **kwargs: calls.__setitem__("editorial", calls["editorial"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "ProductionDetachedRecruiterAssessor",
        lambda **kwargs: calls.__setitem__("recruiter", calls["recruiter"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "prepare_admitted_market_application_from_authorities",
        lambda **kwargs: calls.__setitem__("preparation", calls["preparation"] + 1),
    )

    def replace_resource(current_stage: str) -> None:
        if current_stage != stage:
            return
        path = paths[resource_name]
        if path.is_dir():
            displaced = path.with_name(path.name + "-pinned")
            path.rename(displaced)
            path.mkdir(mode=0o700)
            return
        mode = path.stat().st_mode & 0o777
        content = path.read_bytes()
        path.unlink()
        path.write_bytes(content)
        path.chmod(mode)

    with pytest.raises(
        runner.ProductionPreparationDeploymentError,
        match="changed during operation|descriptor differs",
    ):
        runner._run_production_preparation(
            "app_" + "1" * 64,
            deployment,
            after_preflight_hook=replace_resource,
        )
    assert calls == {"editorial": 0, "recruiter": 0, "preparation": 0}


def test_after_preflight_authority_ancestor_replacement_fails_before_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment, paths = _real_preflight_deployment(monkeypatch, tmp_path)
    calls = {"editorial": 0, "recruiter": 0}
    monkeypatch.setattr(
        runner,
        "DetachedCodexEditorialAdapter",
        lambda **kwargs: calls.__setitem__("editorial", calls["editorial"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "ProductionDetachedRecruiterAssessor",
        lambda **kwargs: calls.__setitem__("recruiter", calls["recruiter"] + 1),
    )

    def replace_ancestor(stage: str) -> None:
        if stage != "resources":
            return
        parent = paths["candidate"].parent
        content = paths["candidate"].read_bytes()
        displaced = parent.with_name(parent.name + "-pinned")
        parent.rename(displaced)
        parent.mkdir(mode=0o700)
        replacement = parent / paths["candidate"].name
        replacement.write_bytes(content)
        replacement.chmod(0o600)

    with pytest.raises(
        runner.ProductionPreparationDeploymentError,
        match="directory changed during operation",
    ):
        runner._run_production_preparation(
            "app_" + "1" * 64,
            deployment,
            after_preflight_hook=replace_ancestor,
        )
    assert calls == {"editorial": 0, "recruiter": 0}


def test_cli_help_bootstraps_from_unrelated_locked_working_directory(
    tmp_path: Path,
) -> None:
    script = (
        Path(__file__).resolve().parent
        / "scripts"
        / "run_production_application_preparation.py"
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--application-id" in completed.stdout
