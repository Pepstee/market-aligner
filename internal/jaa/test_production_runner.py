from __future__ import annotations

import hashlib
import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import career_automation.production_runner as runner_module
from career_automation.application_archive import VacancyArchiveIdentity
from career_automation.application_compiler import CandidateContact
from career_automation.candidate_application_factory import CandidateApplicationPackage
from career_automation.production_queue import LiveVacancy
from career_automation.production_attempt import GreenhouseAttemptRecorder
from career_automation.production_runner import (
    GeneratedRevisionSink,
    GreenhouseProductionRunner,
    ProductionRunCandidate,
)


ROOT = Path(__file__).resolve().parent
AUTHORITY_PATH = Path(
    "/home/gutua/software-factory/application-artifacts/candidate-authorities/"
    "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9.json"
)
DISCOVERY_PATH = Path(
    "/home/gutua/software-factory/application-artifacts/objects/39/"
    "39e60f8d278d8a07427c8bc25eff85bd357e98451cce87983d70d3d85e935f47"
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _candidate() -> ProductionRunCandidate:
    vacancy = VacancyArchiveIdentity(
        job_key="greenhouse:example:123",
        vacancy_sha256=_digest("vacancy"),
        role_title="Engineer",
        company_name="Example",
        source_url="https://job-boards.greenhouse.io/example/jobs/123",
    )
    return ProductionRunCandidate(
        vacancy=LiveVacancy.create(
            vacancy=vacancy,
            provider="greenhouse",
            fit_score="0.2",
            live=True,
            eligible=True,
            duplicate=False,
            live_verified_at=datetime.now(timezone.utc).isoformat(),
            scoring_inputs_sha256=_digest("score"),
        ),
        complete_vacancy=b"complete vacancy",
        structured_vacancy={"job_key": vacancy.job_key},
        assessment={"fit_score": 0.2},
    )


def _package(
    *,
    cv_text: str = "cv",
    cv_pdf: bytes = b"cv pdf",
    letter_text: str = "letter",
    letter_pdf: bytes = b"letter pdf",
    answers_text: str = "answers",
) -> CandidateApplicationPackage:
    return CandidateApplicationPackage(
        source=SimpleNamespace(document=lambda: {"source": "approved"}),
        artifacts=SimpleNamespace(
            editable=SimpleNamespace(
                cv_text=cv_text,
                cover_letter_text=letter_text,
                answers_text=answers_text,
            ),
            cv_pdf=SimpleNamespace(pdf_bytes=cv_pdf),
            cover_letter_pdf=SimpleNamespace(pdf_bytes=letter_pdf),
        ),
        vacancy_requirements=("essential: requirement",),
    )


def _generate_owned(
    sink: GeneratedRevisionSink,
) -> CandidateApplicationPackage:
    authority = json.loads(AUTHORITY_PATH.read_bytes())
    discovery = json.loads(DISCOVERY_PATH.read_bytes())
    decision = next(
        row["receipt"]
        for row in authority["decisions"]
        if row["receipt"]["decision"] == "eligible"
    )
    vacancy = next(
        row
        for row in discovery["live_pending_eligibility"]
        if row["job_key"] == decision["job_key"]
    )
    result = sink.generate_candidate_application(
        decision_receipt=decision,
        candidate_projection=authority["candidate_projection"],
        job_key=vacancy["job_key"],
        vacancy_sha256=vacancy["vacancy_sha256"],
        source_url=vacancy["source_url"],
        role_title=vacancy["role_title"],
        company_name=vacancy["company_name"],
        contact=CandidateContact(
            full_name="Alex Example",
            email="alex@example.test",
            phone=None,
            city="London",
            record_id="operator-contact-primary",
            record_version=1,
            provenance_sha256="a" * 64,
        ),
    )
    assert isinstance(result, CandidateApplicationPackage)
    return result


def _durable_sink(
    tmp_path: Path,
) -> tuple[GeneratedRevisionSink, GreenhouseAttemptRecorder]:
    candidate = _candidate()
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=tmp_path / "archive",
        repository_root=ROOT,
        vacancy=candidate.vacancy.vacancy,
        complete_vacancy=candidate.complete_vacancy,
        structured_vacancy=candidate.structured_vacancy,
        assessment=candidate.assessment,
    )
    return GeneratedRevisionSink(recorder), recorder


def test_runner_wires_queue_recorder_release_authority_and_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeAttempt:
        def _events(self):
            return ()

        def _objects(self, _events):
            return ()

    class FakeRecorder:
        attempt = FakeAttempt()

        def attach_page_evidence(self, _page):
            calls.append("attach_evidence")

        def record_navigation(self, _navigation):
            calls.append("record_navigation")

        def record_prefill(self, _page):
            calls.append("record_prefill")

        def finalize_release(self, _page, **_kwargs):
            calls.append("finalize_release")
            return SimpleNamespace(attempt_id="attempt")

        def add_revision(self, **_kwargs):
            calls.append("add_revision")
            return None

        def finalize_preintent_failure(self, _page, **_kwargs):
            calls.append("finalize_preintent_failure")

    class FakeSink:
        pass

    monkeypatch.setattr(
        runner_module.GreenhouseAttemptRecorder,
        "create",
        lambda **_kwargs: calls.append("create_attempt") or FakeRecorder(),
    )
    monkeypatch.setattr(
        runner_module, "GeneratedRevisionSink", lambda _recorder: FakeSink()
    )
    monkeypatch.setattr(
        GreenhouseProductionRunner,
        "_validate_generation_inventory",
        staticmethod(lambda _prepared, _sink: calls.append("validate_generation")),
    )
    monkeypatch.setattr(
        runner_module,
        "CandidateReleaseExecutionAuthority",
        lambda **_kwargs: calls.append("release_authority") or object(),
    )
    runner = GreenhouseProductionRunner(
        repository_root=ROOT,
        archive_root=tmp_path / "archive",
    )
    receipt = object()
    runner.executor.execute = lambda *_args, **_kwargs: (
        calls.append("executor") or receipt
    )
    runner.executor.boundary_signals = lambda _page: ()
    package = _package()
    prepared = SimpleNamespace(
        source=SimpleNamespace(job_key="greenhouse:example:123"),
        artifacts=package.artifacts,
        contact=object(),
        questions=None,
        document_assurance_receipts=object(),
        sanity_review_receipt=object(),
        production_identity=object(),
        attached_roles=("cv",),
        upload_field_names=(("cv", "resume"),),
        field_authority_names=(("email", "contact.email"),),
        consent_states=(),
        success_evidence=object(),
        success_observation=b"observation",
        gate=object(),
        release_token="token",
        artifact_root=tmp_path,
        upload_paths={"cv": tmp_path / "cv.pdf"},
        application_url="https://job-boards.greenhouse.io/example/jobs/123",
        application_id="123",
        receipt_url="https://job-boards.greenhouse.io/example/jobs/123/confirmation",
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=datetime.now(timezone.utc),
        vacancy_requirements=("essential: requirement",),
        submit_button_name="Submit Application",
        timeout_ms=1000,
    )

    def prepare(_item, _recorder, _page, sink):
        calls.append("prepare_release")
        prepared.generation_authority = object()
        return prepared

    result = runner.execute_next(
        object(),
        candidates=(_candidate(),),
        open_vacancy=lambda _item, _page: calls.append("open_vacancy"),
        prepare_release=prepare,
    )
    assert result is receipt
    assert calls == [
        "create_attempt",
        "attach_evidence",
        "open_vacancy",
        "record_navigation",
        "record_prefill",
        "prepare_release",
        "validate_generation",
        "finalize_release",
        "release_authority",
        "executor",
    ]


def test_executable_runner_requires_explicit_live_acknowledgement() -> None:
    with pytest.raises(SystemExit):
        runner_module.main(
            [
                "--repository-root",
                str(ROOT),
                "--archive-root",
                str(ROOT.parent / "application-artifacts-test"),
            ]
        )


def test_runner_rejects_external_factory_substitution() -> None:
    with pytest.raises(ValueError, match="repository production factory"):
        runner_module._load_factory("attacker.factory:create_session")


def test_execute_all_can_stop_after_one_terminal_attempt(tmp_path: Path) -> None:
    runner = GreenhouseProductionRunner(
        repository_root=ROOT,
        archive_root=tmp_path / "archive",
    )
    candidate = _candidate()
    calls = 0

    def execute_next(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return object()

    runner.execute_next = execute_next
    receipts = runner.execute_all(
        object(),
        candidates=(candidate,),
        open_vacancy=lambda *_args: None,
        prepare_release=lambda *_args: None,
        max_terminal_attempts=1,
    )
    assert calls == 1
    assert len(receipts) == 1


def test_execute_all_rejects_nonpositive_attempt_limit(tmp_path: Path) -> None:
    runner = GreenhouseProductionRunner(
        repository_root=ROOT,
        archive_root=tmp_path / "archive",
    )
    with pytest.raises(ValueError, match="at least one"):
        runner.execute_all(
            object(),
            candidates=(),
            open_vacancy=lambda *_args: None,
            prepare_release=lambda *_args: None,
            max_terminal_attempts=0,
        )


def test_runner_rejects_incomplete_final_generation_inventory(
    tmp_path: Path,
) -> None:
    sink, _recorder = _durable_sink(tmp_path)
    generated = _generate_owned(sink)
    prepared = SimpleNamespace(
        generation_authority=sink.seal(),
        source=generated.source,
        artifacts=_package(cv_text="unarchived replacement").artifacts,
    )
    with pytest.raises(ValueError, match="absent from revision inventory"):
        GreenhouseProductionRunner._validate_generation_inventory(prepared, sink)


def test_owned_product_generation_archives_complete_bundle_before_return(
    tmp_path: Path,
) -> None:
    sink, _recorder = _durable_sink(tmp_path)
    returned = _generate_owned(sink)
    assert isinstance(returned, CandidateApplicationPackage)
    assert [row.role for row in sink.revisions[:4]] == [
        "generation.inputs",
        "document.source_inputs",
        "document.cv.constraints",
        "document.cv.source",
    ]
    assert sink.revisions[4].role == "document.cv.final_pdf"
    assert sink.revisions[3].value == returned.artifacts.editable.cv_text.encode()
    assert sink.revisions[4].value == returned.artifacts.cv_pdf.pdf_bytes
    assert len(sink.seal().archive_event_sha256s) == 9
    assert sink.revisions[-1].role == "generation.package_pickle"


def test_bundle_preserves_all_generated_bytes_when_later_archive_write_crashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, bytes]] = []
    sink, recorder = _durable_sink(tmp_path)
    original_add_revision = recorder.add_revision

    def crash(**kwargs):
        calls.append((kwargs["role"], kwargs["value"]))
        if len(calls) == 2:
            raise OSError("injected revision write crash")
        return original_add_revision(**kwargs)

    monkeypatch.setattr(recorder, "add_revision", crash)
    with pytest.raises(OSError, match="injected"):
        _generate_owned(sink)
    assert calls[0][0] == "generation.inputs"
    assert calls[1][0] == "document.source_inputs"


def test_runner_archives_returned_revisions_before_inventory_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    monkeypatch.setattr(
        GreenhouseAttemptRecorder, "record_prefill", lambda self, _page: None
    )
    monkeypatch.setattr(
        GreenhouseAttemptRecorder,
        "attach_page_evidence",
        lambda self, _page: None,
    )
    monkeypatch.setattr(
        GreenhouseAttemptRecorder,
        "record_navigation",
        lambda self, _navigation: None,
    )
    monkeypatch.setattr(
        GreenhouseAttemptRecorder,
        "finalize_preintent_failure",
        lambda self, _page, **kwargs: calls.append(f"terminal:{kwargs['reason_code']}"),
    )
    runner = GreenhouseProductionRunner(
        repository_root=ROOT,
        archive_root=tmp_path / "archive",
    )
    runner.executor.boundary_signals = lambda _page: ()
    prepared = SimpleNamespace(
        artifacts=_package(cv_text="unarchived replacement").artifacts,
    )
    with pytest.raises(ValueError, match="absent from revision inventory"):

        def prepare(_item, _recorder, _page, sink):
            generated = _generate_owned(sink)
            prepared.source = generated.source
            prepared.generation_authority = sink.seal()
            return prepared

        runner.execute_next(
            object(),
            candidates=(_candidate(),),
            open_vacancy=lambda _item, _page: None,
            prepare_release=prepare,
        )
    assert calls == ["terminal:generation_inventory_rejected"]


def test_generation_sink_archives_observed_rejected_revision() -> None:
    calls: list[str] = []

    class Recorder:
        def add_revision(self, **kwargs):
            calls.append(kwargs["role"])

    sink = GeneratedRevisionSink(Recorder())  # type: ignore[arg-type]
    sink.archive_revision(
        role="document.cv.source",
        media_type="text/plain",
        value=b"draft",
        prior_sha256=None,
        approved=False,
        rejection_codes=("generator_crashed",),
    )
    assert calls == ["document.cv.source"]
    assert sink.revisions[0].value == b"draft"


def test_caller_supplied_hidden_product_callback_cannot_authorize_release() -> None:
    class Recorder:
        def add_revision(self, **_kwargs):
            return None

    sink = GeneratedRevisionSink(Recorder())  # type: ignore[arg-type]
    assert not hasattr(sink, "generate_product")
    sink.archive_revision(
        role="document.cover_letter.source",
        media_type="text/plain",
        value=b"reported final only",
        prior_sha256=None,
        approved=True,
    )
    with pytest.raises(ValueError, match="only completed owned generation"):
        sink.seal()


def test_runtime_factory_replacement_cannot_hide_a_rejected_draft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import career_automation.candidate_application_factory as factory_module

    called = False

    def hidden_draft_factory(**_kwargs):
        nonlocal called
        called = True
        return _package(cv_text="reported final after hidden rejected draft")

    monkeypatch.setattr(
        factory_module, "build_candidate_application_package", hidden_draft_factory
    )
    assert not hasattr(runner_module, "_OWNED_BUILD_CANDIDATE_APPLICATION_PACKAGE")

    sink, _recorder = _durable_sink(tmp_path)
    _generate_owned(sink)
    assert called is False
    assert sink.seal().generator_identity == runner_module.OWNED_CANDIDATE_GENERATOR


def test_runtime_renderer_replacement_cannot_create_a_hidden_draft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import career_automation.candidate_application_factory as factory_module

    called = False
    original = factory_module.render_pdf_artifacts

    def hidden_renderer(source):
        nonlocal called
        called = True
        original(source)
        return original(source)

    monkeypatch.setattr(factory_module, "render_pdf_artifacts", hidden_renderer)
    sink, _recorder = _durable_sink(tmp_path)
    _generate_owned(sink)
    assert called is False
    assert sink.seal().repository_head == runner_module.exact_clean_head(ROOT)


def test_instance_generator_substitution_is_not_an_invocation_hook(
    tmp_path: Path,
) -> None:
    sink, _recorder = _durable_sink(tmp_path)
    called = False

    def substituted(_arguments):
        nonlocal called
        called = True
        return _package()

    sink._run_isolated_generator = substituted  # type: ignore[attr-defined]
    package = _generate_owned(sink)
    assert called is False
    archived_package = next(
        row for row in sink.seal().revisions if row.role == "generation.package_pickle"
    )
    assert archived_package.value
    assert (
        runner_module.canonical_json(package.source.document()) + "\n"
    ).encode() == next(
        row.value for row in sink.revisions if row.role == "document.source_inputs"
    )


def test_module_generator_wrapper_is_not_an_invocation_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def hidden_draft_wrapper(*_args, **_kwargs):
        nonlocal called
        called = True
        return _package(cv_text="reported final after hidden intermediate")

    assert not hasattr(runner_module, "_run_isolated_generation")
    monkeypatch.setattr(
        runner_module,
        "_run_isolated_generation",
        hidden_draft_wrapper,
        raising=False,
    )
    sink, _recorder = _durable_sink(tmp_path)
    package = _generate_owned(sink)
    assert called is False
    archived_package = next(
        row for row in sink.seal().revisions if row.role == "generation.package_pickle"
    )
    assert pickle.loads(archived_package.value) == package


def test_nonstandard_recorder_and_private_state_cannot_mint_authority() -> None:
    class Recorder:
        def add_revision(self, **_kwargs):
            return None

    sink = GeneratedRevisionSink(Recorder())  # type: ignore[arg-type]
    for role in (
        "generation.inputs",
        "document.source_inputs",
        "document.cv.source",
        "document.cv.final_pdf",
        "document.cover_letter.source",
        "document.cover_letter.final_pdf",
        "form.answers",
    ):
        sink.archive_revision(
            role=role,
            media_type="application/octet-stream",
            value=role.encode(),
            prior_sha256=None,
            approved=True,
        )
    assert not hasattr(sink, "_build_authority")
    sink._authority = SimpleNamespace()  # type: ignore[assignment]
    with pytest.raises(ValueError, match="durable recorder receipts"):
        sink.seal()


def test_mutating_legacy_private_flags_cannot_authorize_observed_outputs() -> None:
    class Recorder:
        def add_revision(self, **_kwargs):
            return None

    sink = GeneratedRevisionSink(Recorder())  # type: ignore[arg-type]
    sink.archive_revision(
        role="document.cv.source",
        media_type="text/plain",
        value=b"caller-selected output",
        prior_sha256=None,
        approved=True,
    )
    sink._generator_identity = runner_module.OWNED_CANDIDATE_GENERATOR  # type: ignore[attr-defined]
    sink._owned_generation_complete = True  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="only completed owned generation"):
        sink.seal()


def test_sealed_sink_rejects_late_revision(tmp_path: Path) -> None:
    sink, _recorder = _durable_sink(tmp_path)
    _generate_owned(sink)
    sink.seal()
    with pytest.raises(ValueError, match="sealed"):
        sink.archive_revision(
            role="document.cv.source",
            media_type="text/plain",
            value=b"late",
            prior_sha256=hashlib.sha256(b"final").hexdigest(),
            approved=True,
        )


def test_runner_terminalizes_after_sink_archives_generator_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeAttempt:
        def _events(self):
            return ()

        def _objects(self, _events):
            return ()

    class FakeRecorder:
        attempt = FakeAttempt()

        def attach_page_evidence(self, _page):
            return None

        def record_navigation(self, _navigation):
            return None

        def record_prefill(self, _page):
            return None

        def add_revision(self, **kwargs):
            calls.append(f"archive:{kwargs['role']}")

        def finalize_preintent_failure(self, _page, **kwargs):
            calls.append(f"terminal:{kwargs['reason_code']}")

    monkeypatch.setattr(
        runner_module.GreenhouseAttemptRecorder,
        "create",
        lambda **_kwargs: FakeRecorder(),
    )
    runner = GreenhouseProductionRunner(
        repository_root=ROOT,
        archive_root=tmp_path / "archive",
    )
    runner.executor.boundary_signals = lambda _page: ()

    def crash(_item, _recorder, _page, sink):
        sink.archive_revision(
            role="document.cv.source",
            media_type="text/plain",
            value=b"partial draft",
            prior_sha256=None,
            approved=False,
            rejection_codes=("generation_interrupted",),
        )
        raise RuntimeError("generator stopped")

    with pytest.raises(RuntimeError, match="generator stopped"):
        runner.execute_next(
            object(),
            candidates=(_candidate(),),
            open_vacancy=lambda _item, _page: None,
            prepare_release=crash,
        )
    assert calls == [
        "archive:document.cv.source",
        "terminal:release_preparation_failed",
    ]


def test_runner_terminalizes_observed_provider_boundary_before_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeAttempt:
        def _events(self):
            return ()

        def _objects(self, _events):
            return ()

    class FakeRecorder:
        attempt = FakeAttempt()

        def attach_page_evidence(self, _page):
            return None

        def record_navigation(self, _navigation):
            return None

        def finalize_provider_boundary(self, _page, **kwargs):
            calls.append("terminal_boundary")
            assert kwargs["signals"] == ("recaptcha",)
            assert kwargs["network_evidence"][-1]["status"] == 200

        def record_prefill(self, _page):
            pytest.fail("prefill must not run across a provider boundary")

    monkeypatch.setattr(
        runner_module.GreenhouseAttemptRecorder,
        "create",
        lambda **_kwargs: calls.append("create_attempt") or FakeRecorder(),
    )
    runner = GreenhouseProductionRunner(
        repository_root=ROOT,
        archive_root=tmp_path / "archive",
    )
    runner.executor.boundary_signals = lambda _page: ("recaptcha",)
    result = runner.execute_next(
        object(),
        candidates=(_candidate(),),
        open_vacancy=lambda _item, _page: {
            "url": "https://job-boards.greenhouse.io/example/jobs/123",
            "status": 200,
            "method": "GET",
            "redirected_from": None,
        },
        prepare_release=lambda *_args: pytest.fail(
            "preparation must not run across a provider boundary"
        ),
    )
    assert result is None
    assert calls == ["create_attempt", "terminal_boundary"]
