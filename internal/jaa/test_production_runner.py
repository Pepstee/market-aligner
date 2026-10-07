from __future__ import annotations

import hashlib
import json
import os
import pickle
import subprocess
import sys
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
from career_automation.production_ats_executor import ProductionSubmissionReceipt
from career_automation.production_runner import (
    GeneratedRevisionSink,
    GreenhouseProductionRunner,
    ProductionRunCandidate,
    ReviewOnlyCompletion,
)


ROOT = Path(__file__).resolve().parent


def test_cli_help_bootstraps_from_unrelated_working_directory(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "run_greenhouse_production.py"
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
    assert "--execute-live" in completed.stdout
    assert "--review-only" in completed.stdout
    assert "--current-runtime-config" in completed.stdout
    assert "--current-runtime-config-sha256" in completed.stdout
    assert "--current-runtime-private-root" in completed.stdout
    assert "--current-recovery-manifest-relative-path" in completed.stdout


def test_browser_runtime_cli_options_are_explicit_and_separated(tmp_path: Path) -> None:
    parser = runner_module._build_parser()
    common = [
        "--repository-root", str(tmp_path),
        "--archive-root", str(tmp_path),
        "--review-only",
    ]
    legacy = runner_module.browser_runtime_options(parser.parse_args(common))
    assert legacy["current_runtime"] is False
    assert legacy["admission_kwargs"] == {}
    assert legacy["materialization_kwargs"] == {}
    assert legacy["selection_kwargs"] == {}
    assert legacy["admission_kwargs"] is not legacy["selection_kwargs"]

    values = {
        "--current-runtime-config": str(tmp_path / "runtime.json"),
        "--current-runtime-config-sha256": "a" * 64,
        "--current-runtime-private-root": str(tmp_path / "private"),
        "--current-recovery-manifest-relative-path": "recovered/manifest.json",
    }
    argv = [
        *common,
        "--market-execution-receipt",
        str(tmp_path / "execution.json"),
    ]
    for flag, value in values.items():
        argv.extend((flag, value))
    options = runner_module.browser_runtime_options(parser.parse_args(argv))
    shared = {
        "current_runtime_config_path": values["--current-runtime-config"],
        "current_runtime_config_sha256": values["--current-runtime-config-sha256"],
        "current_runtime_private_root": values["--current-runtime-private-root"],
    }
    assert options["current_runtime"] is True
    assert options["admission_kwargs"] == shared
    assert options["selection_kwargs"] == shared
    assert options["materialization_kwargs"] == {
        **shared,
        "current_recovery_manifest_relative_path": "recovered/manifest.json",
    }


def test_browser_runtime_cli_options_reject_partial_or_invalid_bindings(
    tmp_path: Path,
) -> None:
    import itertools

    parser = runner_module._build_parser()
    common = [
        "--repository-root", str(tmp_path),
        "--archive-root", str(tmp_path),
        "--review-only",
    ]
    flags = {
        "current_runtime_config_path": "--current-runtime-config",
        "current_runtime_config_sha256": "--current-runtime-config-sha256",
        "current_runtime_private_root": "--current-runtime-private-root",
        "current_recovery_manifest_relative_path": (
            "--current-recovery-manifest-relative-path"
        ),
    }
    values = {
        "current_runtime_config_path": str(tmp_path / "runtime.json"),
        "current_runtime_config_sha256": "a" * 64,
        "current_runtime_private_root": str(tmp_path / "private"),
        "current_recovery_manifest_relative_path": "recovered/manifest.json",
    }
    for count in (1, 2, 3):
        for names in itertools.combinations(flags, count):
            argv = list(common)
            for name in names:
                argv.extend((flags[name], values[name]))
            parsed = parser.parse_args(argv)
            with pytest.raises(ValueError, match="all four"):
                runner_module.browser_runtime_options(parsed)

    complete = [
        *common,
        "--market-execution-receipt",
        str(tmp_path / "execution.json"),
    ]
    for name, flag in flags.items():
        complete.extend((flag, values[name]))
    parsed = parser.parse_args(complete)

    class StringSubclass(str):
        pass

    parsed.current_runtime_config_path = StringSubclass(
        parsed.current_runtime_config_path
    )
    with pytest.raises(ValueError, match="must be a string"):
        runner_module.browser_runtime_options(parsed)
    parsed.current_runtime_config_path = values["current_runtime_config_path"]
    parsed.current_runtime_config_sha256 = "A" * 64
    with pytest.raises(ValueError, match="lowercase hex"):
        runner_module.browser_runtime_options(parsed)
    parsed.current_runtime_config_sha256 = "a" * 64
    parsed.current_recovery_manifest_relative_path = "../manifest.json"
    with pytest.raises(ValueError, match="confined relative path"):
        runner_module.browser_runtime_options(parsed)
    parsed.current_recovery_manifest_relative_path = "recovered/manifest.json"
    parsed.market_execution_receipt = None
    with pytest.raises(ValueError, match="market_execution_receipt"):
        runner_module.browser_runtime_options(parsed)


@pytest.mark.parametrize("terminal_pending", [False, "event", "summary"])
def test_review_only_runner_completes_without_release_and_does_not_reenter(tmp_path, monkeypatch, terminal_pending):
    from test_application_archive import _review_preparation
    from career_automation.production_runner import ReviewOnlyCompletion

    recorder, prepared = _review_preparation(tmp_path)
    if terminal_pending:
        def interrupted(**kwargs):
            raise RuntimeError("synthetic interruption before terminal manifest")

        with monkeypatch.context() as patch:
            if terminal_pending == "summary":
                import career_automation.application_archive as archive_module
                atomic_create = archive_module._atomic_create

                def interrupt_manifest(path, value, **kwargs):
                    if path.name == "terminal-manifest.json":
                        interrupted()
                    return atomic_create(path, value, **kwargs)

                patch.setattr(archive_module, "_atomic_create", interrupt_manifest)
            else:
                patch.setattr(recorder.attempt, "finalize_terminal", interrupted)
            with pytest.raises(RuntimeError, match="synthetic interruption"):
                recorder.finalize_review_only(prepared)
    prior_summary = ((recorder.attempt.path / "terminal-summary.txt").read_bytes()
                     if terminal_pending == "summary" else None)
    original_events = recorder.attempt._events()
    original_objects = tuple((row, recorder.attempt.read_artifact(row))
                             for row in recorder.attempt._objects(original_events))
    candidate = ProductionRunCandidate(
        vacancy=LiveVacancy.create(
            vacancy=recorder.attempt.vacancy, provider="greenhouse", fit_score="0.2",
            live=True, eligible=True, duplicate=False,
            live_verified_at=datetime.now(timezone.utc).isoformat(),
            scoring_inputs_sha256=_digest("review-score"),
        ),
        complete_vacancy=b"vacancy", structured_vacancy={}, assessment={},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("release or submission authority reached")

    monkeypatch.setattr(runner_module, "CertifiedGreenhouseSubmitExecutor", forbidden)
    monkeypatch.setattr(runner_module, "CandidateReleaseExecutionAuthority", forbidden)
    monkeypatch.setattr(GreenhouseAttemptRecorder, "finalize_release", forbidden)
    monkeypatch.setattr(GreenhouseAttemptRecorder, "create", forbidden)
    validated = []
    monkeypatch.setattr(GreenhouseProductionRunner, "_validate_generation_inventory",
                        staticmethod(lambda result, sink: validated.append(result)))
    runner = GreenhouseProductionRunner(repository_root=recorder.attempt.archive.repository_root,
                                       archive_root=recorder.attempt.archive.root, review_only=True)
    routes = []
    page = SimpleNamespace(on=lambda *args: None, route=lambda pattern, handler: routes.append(handler))
    completed = runner.execute_all(page, candidates=(candidate,),
                                   open_vacancy=forbidden if terminal_pending else lambda *args: {"method": "GET", "status": 200, "url": candidate.vacancy.vacancy.source_url},
                                   prepare_review=forbidden if terminal_pending else lambda *args: prepared)
    assert len(completed) == 1 and type(completed[0]) is ReviewOnlyCompletion
    assert completed[0].attempt_id == recorder.attempt.attempt_id
    assert recorder.attempt._events()[:len(original_events)] == original_events
    assert sum(row.role == "review.intent" for row in recorder.attempt._objects(recorder.attempt._events())) == 1
    for row, raw in original_objects:
        assert recorder.attempt.read_artifact(row) == raw
    assert validated == ([] if terminal_pending else [prepared])
    assert runner._queue((candidate,)).next_action is None
    if terminal_pending:
        assert recorder.attempt._events() == original_events
        assert routes == []
        if prior_summary is not None:
            assert (recorder.attempt.path / "terminal-summary.txt").read_bytes() == prior_summary
        return
    actions = []
    routes[0](SimpleNamespace(request=SimpleNamespace(method="POST"),
                              abort=lambda: actions.append("abort"),
                              continue_=forbidden))
    assert actions == ["abort"]


def test_review_only_runner_rejects_incomplete_release_before_browser_access(tmp_path, monkeypatch):
    candidate = _candidate()
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=tmp_path / "archive", repository_root=ROOT,
        vacancy=candidate.vacancy.vacancy, complete_vacancy=b"vacancy",
        structured_vacancy={}, assessment={},
    )
    recorder._add("browser.prefill_snapshot", b"{}", "application/json")
    original = recorder.attempt._events()

    def forbidden(*args, **kwargs):
        raise AssertionError("review recovery reached browser or release authority")

    monkeypatch.setattr(runner_module, "CertifiedGreenhouseSubmitExecutor", forbidden)
    monkeypatch.setattr(runner_module, "CandidateReleaseExecutionAuthority", forbidden)
    runner = GreenhouseProductionRunner(repository_root=ROOT, archive_root=tmp_path / "archive", review_only=True)
    with pytest.raises(ValueError, match="no review-only intent"):
        runner.execute_next(None, candidates=(candidate,), open_vacancy=forbidden, prepare_review=forbidden)
    assert recorder.attempt._events() == original


def test_review_only_runner_never_constructs_submit_executor(tmp_path, monkeypatch):
    def forbidden(**kwargs):
        raise AssertionError("submit executor reached")

    monkeypatch.setattr(runner_module, "CertifiedGreenhouseSubmitExecutor", forbidden)
    runner = GreenhouseProductionRunner(repository_root=ROOT, archive_root=tmp_path / "archive", review_only=True)
    assert runner.executor is None
    with pytest.raises(ValueError, match="only a review"):
        runner.execute_next(None, candidates=(), open_vacancy=None, prepare_release=lambda *args: None)
    with pytest.raises(ValueError, match="one terminal"):
        runner.execute_all(None, candidates=(), open_vacancy=None, prepare_review=lambda *args: None, max_terminal_attempts=2)


@pytest.mark.parametrize("flags", [[], ["--review-only", "--execute-live"], ["--review-only", "--max-terminal-attempts", "2"]])
def test_review_only_cli_selection_is_explicit_and_bounded(tmp_path, monkeypatch, flags):
    def forbidden(*args):
        raise AssertionError("session factory must not run")

    monkeypatch.setattr(runner_module, "_load_factory", forbidden)
    with pytest.raises(SystemExit) as exc:
        runner_module.main(["--repository-root", str(ROOT), "--archive-root", str(tmp_path), *flags])
    assert exc.value.code == 2


@pytest.mark.parametrize("attempt_limit", [None, 2])
def test_live_runner_requires_exactly_one_terminal_attempt(tmp_path, attempt_limit):
    runner = GreenhouseProductionRunner(repository_root=ROOT, archive_root=tmp_path / "archive")
    with pytest.raises(ValueError, match="exactly one terminal"):
        runner.execute_all(
            None, candidates=(), open_vacancy=lambda *args: None,
            prepare_release=lambda *args: None, max_terminal_attempts=attempt_limit,
        )


@pytest.mark.parametrize("flags", [["--execute-live"], ["--execute-live", "--max-terminal-attempts", "2"]])
def test_live_cli_requires_exactly_one_terminal_attempt(tmp_path, monkeypatch, flags):
    def forbidden(*args):
        raise AssertionError("session factory must not run")

    monkeypatch.setattr(runner_module, "_load_factory", forbidden)
    with pytest.raises(SystemExit) as exc:
        runner_module.main(["--repository-root", str(ROOT), "--archive-root", str(tmp_path), *flags])
    assert exc.value.code == 2


def test_live_cli_accepts_one_terminal_attempt(tmp_path, monkeypatch):
    def reached_factory(*args):
        raise AssertionError("valid canary arguments reached the session factory")

    monkeypatch.setattr(runner_module, "_load_factory", reached_factory)
    with pytest.raises(AssertionError, match="valid canary arguments"):
        runner_module.main([
            "--repository-root", str(ROOT), "--archive-root", str(tmp_path),
            "--execute-live", "--max-terminal-attempts", "1",
        ])


def _submission_receipt(*, job_key: str, vacancy_sha256: str) -> ProductionSubmissionReceipt:
    document = {
        "schema_version": "jaa.production-submission-receipt.v1",
        "attempt_id": "jaa-20260928T000000Z-0123456789abcdef",
        "provider": "greenhouse",
        "job_key": job_key,
        "vacancy_sha256": vacancy_sha256,
        "confirmation_url": "https://job-boards.greenhouse.io/example/confirmation",
        "page_title": "Application received",
        "visible_text_sha256": "1" * 64,
        "post_submit_screenshot_sha256": "2" * 64,
        "submitted_at": "2026-09-28T00:00:00Z",
        "provider_application_id": None,
        "confirmation_email_checked": False,
    }
    receipt_sha256 = hashlib.sha256(
        (runner_module.canonical_json(document) + "\n").encode()
    ).hexdigest()
    return ProductionSubmissionReceipt(
        **document,
        receipt_sha256=receipt_sha256,
    )


def _run_cli_with_terminal_result(
    monkeypatch: pytest.MonkeyPatch,
    *,
    outcomes: tuple[object, ...],
    mode: tuple[str, ...],
) -> tuple[int, SimpleNamespace]:
    candidate = _candidate()
    closed: list[bool] = []
    session = SimpleNamespace(
        page=object(),
        candidates=(candidate,),
        open_vacancy=lambda *_args: None,
        prepare_release=lambda *_args: None,
        prepare_review=lambda *_args: None,
        gmail_confirmation_checker=None,
        close=lambda: closed.append(True),
    )

    class FakeRunner:
        def __init__(self, **_kwargs) -> None:
            pass

        def execute_all(self, *_args, **_kwargs):
            return outcomes

    monkeypatch.setattr(runner_module, "_load_factory", lambda _reference: lambda _args: session)
    monkeypatch.setattr(runner_module, "GreenhouseProductionRunner", FakeRunner)
    args = [
        "--repository-root", str(ROOT),
        "--archive-root", str(ROOT / ".test-archive-placeholder"),
        *mode,
    ]
    return runner_module.main(args), SimpleNamespace(session=session, candidate=candidate, closed=closed)


def test_live_cli_returns_success_only_with_matching_submission_receipt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = _candidate()
    source = candidate.vacancy.vacancy
    receipt = _submission_receipt(
        job_key=source.job_key,
        vacancy_sha256=source.vacancy_sha256,
    )
    code, result = _run_cli_with_terminal_result(
        monkeypatch,
        outcomes=(receipt,),
        mode=("--execute-live", "--max-terminal-attempts", "1"),
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["outcome"] == "submitted_success"
    assert output["submission_receipt"]["receipt_sha256"] == receipt.receipt_sha256
    assert result.closed == [True]


def test_live_cli_exits_nonzero_when_no_terminal_submission_receipt_exists(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, result = _run_cli_with_terminal_result(
        monkeypatch,
        outcomes=(),
        mode=("--execute-live", "--max-terminal-attempts", "1"),
    )
    error = json.loads(capsys.readouterr().err)
    assert code == 2
    assert error["outcome"] == "no_terminal_attempt"
    assert error["submission_receipt"] is None
    assert result.closed == [True]


def test_live_cli_rejects_receipt_for_a_different_vacancy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt = _submission_receipt(job_key="other-job", vacancy_sha256="3" * 64)
    code, result = _run_cli_with_terminal_result(
        monkeypatch,
        outcomes=(receipt,),
        mode=("--execute-live", "--max-terminal-attempts", "1"),
    )
    error = json.loads(capsys.readouterr().err)
    assert code == 2
    assert error["outcome"] == "submission_receipt_candidate_mismatch"
    assert result.closed == [True]


def test_review_cli_labels_review_only_without_claiming_submission(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    review = ReviewOnlyCompletion(
        attempt_id="jaa-20260928T000000Z-0123456789abcdef",
        terminal_manifest_sha256="4" * 64,
    )
    code, result = _run_cli_with_terminal_result(
        monkeypatch,
        outcomes=(review,),
        mode=("--review-only",),
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["outcome"] == "review_only"
    assert "submission_receipt" not in output
    assert result.closed == [True]
PRIVATE_AUTHORITY_ROOT = ROOT.parents[1] / ".market-aligner-data" / "authority-inputs"
AUTHORITY_PATH = (
    PRIVATE_AUTHORITY_ROOT
    / "candidate-authorities"
    / ("85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9.json")
)
DISCOVERY_PATH = (
    PRIVATE_AUTHORITY_ROOT
    / "objects"
    / "39"
    / ("39e60f8d278d8a07427c8bc25eff85bd357e98451cce87983d70d3d85e935f47")
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
    if not AUTHORITY_PATH.is_file() or not DISCOVERY_PATH.is_file():
        pytest.skip(
            "requires the exact private Gigabyte candidate-authority and "
            "discovery artifacts; synthetic substitution would not test the "
            "certified binding"
        )
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


def _generator_source_identity_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    package_relative: str = "internal/jaa",
    package_root_override: Path | None = None,
    package_git_root: Path | None = None,
    prefix: str = "internal/jaa/",
    disk_mismatch: str | None = None,
    missing_git_path: str | None = None,
) -> tuple[
    GeneratedRevisionSink,
    dict[str, bytes],
    list[str],
    list[tuple[str, ...]],
]:
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    package_root = (
        repository_root / package_relative
        if package_root_override is None
        else package_root_override
    )
    package_root.mkdir(parents=True, exist_ok=True)
    effective_package_git_root = package_git_root or repository_root
    effective_package_git_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        runner_module,
        "__file__",
        str(package_root / "career_automation" / "production_runner.py"),
    )

    head = "a" * 40
    source_bytes = {
        relative: f"synthetic source: {relative}".encode()
        for relative in runner_module._GENERATOR_SOURCE_PATHS
    }
    disk_bytes = dict(source_bytes)
    if disk_mismatch is not None:
        disk_bytes[disk_mismatch] = b"synthetic disk mismatch"
    local_paths = {
        (package_root / relative).resolve(): relative
        for relative in runner_module._GENERATOR_SOURCE_PATHS
    }
    read_paths: list[str] = []
    original_read_bytes = Path.read_bytes

    def read_bytes(path: Path) -> bytes:
        relative = local_paths.get(path.resolve())
        if relative is None:
            return original_read_bytes(path)
        read_paths.append(relative)
        return disk_bytes[relative]

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    git_commands: list[tuple[str, ...]] = []

    def run_git(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        git_commands.append(tuple(arguments))
        if arguments[:2] != ["git", "-C"]:
            raise AssertionError("unexpected subprocess command")
        directory = Path(arguments[2]).resolve()
        operation = arguments[3:]
        if operation == ["rev-parse", "--show-toplevel"]:
            if directory == repository_root.resolve():
                output = f"{repository_root.resolve()}\n"
            elif directory == package_root.resolve():
                output = f"{effective_package_git_root.resolve()}\n"
            else:
                raise AssertionError("unexpected git top-level query")
        elif operation == ["rev-parse", "--show-prefix"]:
            if directory != package_root.resolve():
                raise AssertionError("prefix must come from the running package root")
            output = f"{prefix}\n"
        elif operation and operation[0] == "show":
            requested_head, separator, committed_path = operation[1].partition(":")
            if not separator or requested_head != head:
                raise AssertionError("unexpected committed source request")
            expected_paths = {
                f"{prefix}{relative}": relative
                for relative in runner_module._GENERATOR_SOURCE_PATHS
            }
            relative = expected_paths.get(committed_path)
            if relative is None or relative == missing_git_path:
                raise subprocess.CalledProcessError(
                    128, arguments, stderr=b"synthetic missing Git path"
                )
            output = source_bytes[relative]
        else:
            raise AssertionError("unexpected git operation")
        if kwargs.get("text"):
            return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr="")
        return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr=b"")

    monkeypatch.setattr(runner_module.subprocess, "run", run_git)
    monkeypatch.setattr(runner_module, "exact_clean_head", lambda _root: head)
    sink = object.__new__(GeneratedRevisionSink)
    sink._recorder = SimpleNamespace(
        attempt=SimpleNamespace(
            archive=SimpleNamespace(repository_root=repository_root)
        )
    )
    return sink, source_bytes, read_paths, git_commands


@pytest.mark.parametrize(
    ("package_relative", "prefix"),
    (("internal/jaa", "internal/jaa/"), ("", "")),
)
def test_generator_source_identity_uses_running_package_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_relative: str,
    prefix: str,
) -> None:
    sink, source_bytes, read_paths, git_commands = _generator_source_identity_fixture(
        tmp_path, monkeypatch, package_relative=package_relative, prefix=prefix
    )

    head, identities = sink._generator_source_identity()

    assert head == "a" * 40
    assert identities == tuple(
        (relative, hashlib.sha256(source_bytes[relative]).hexdigest())
        for relative in runner_module._GENERATOR_SOURCE_PATHS
    )
    assert read_paths == list(runner_module._GENERATOR_SOURCE_PATHS)
    requested = [
        command[4].split(":", 1)[1]
        for command in git_commands
        if len(command) > 4 and command[3] == "show"
    ]
    assert requested == [
        f"{prefix}{relative}" for relative in runner_module._GENERATOR_SOURCE_PATHS
    ]


def test_generator_source_identity_rejects_a_different_git_root_before_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unrelated_root = tmp_path / "unrelated"
    package_root = unrelated_root / "internal" / "jaa"
    sink, _source_bytes, read_paths, git_commands = _generator_source_identity_fixture(
        tmp_path,
        monkeypatch,
        package_root_override=package_root,
        package_git_root=unrelated_root,
    )

    with pytest.raises(ValueError, match="outside the recorder Git repository"):
        sink._generator_source_identity()

    assert read_paths == []
    assert all(command[3:5] == ("rev-parse", "--show-toplevel") for command in git_commands)


def test_generator_source_identity_rejects_noncanonical_package_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink, _source_bytes, read_paths, git_commands = _generator_source_identity_fixture(
        tmp_path, monkeypatch, prefix="internal/jaa"
    )

    with pytest.raises(ValueError, match="repository prefix is not canonical"):
        sink._generator_source_identity()

    assert read_paths == []
    assert all(command[3] != "show" for command in git_commands)


def test_generator_source_identity_rejects_running_byte_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = runner_module._GENERATOR_SOURCE_PATHS[0]
    sink, _source_bytes, read_paths, _git_commands = _generator_source_identity_fixture(
        tmp_path, monkeypatch, disk_mismatch=relative
    )

    with pytest.raises(
        ValueError, match="running candidate generator differs from exact clean HEAD"
    ):
        sink._generator_source_identity()

    assert read_paths == [relative]


def test_generator_source_identity_propagates_missing_committed_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = runner_module._GENERATOR_SOURCE_PATHS[0]
    sink, _source_bytes, read_paths, _git_commands = _generator_source_identity_fixture(
        tmp_path, monkeypatch, missing_git_path=relative
    )

    with pytest.raises(subprocess.CalledProcessError):
        sink._generator_source_identity()

    assert read_paths == []


def test_generator_source_identity_propagates_exact_clean_head_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink, _source_bytes, read_paths, git_commands = _generator_source_identity_fixture(
        tmp_path, monkeypatch
    )

    def reject_dirty_head(_repository: Path) -> str:
        raise ValueError("synthetic exact-clean-head refusal")

    monkeypatch.setattr(runner_module, "exact_clean_head", reject_dirty_head)
    with pytest.raises(ValueError, match="synthetic exact-clean-head refusal"):
        sink._generator_source_identity()

    assert git_commands == []
    assert read_paths == []


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
        form_answer_bindings=(),
        review_form_fields=None,
        form_field_authorities=(),
        form_inventory_sha256=None,
        document_assurance_receipts=object(),
        sanity_review_receipt=object(),
        ats_application_authority=object(),
        quality_input=object(),
        quality_review=object(),
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
        vacancy_review_material=object(),
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


@pytest.mark.parametrize("failure", [False, True])
def test_private_worker_channel_archives_real_child_revisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: bool,
) -> None:
    """Real child/pipe/archive, synthetic generator only; no candidate corpus."""
    import base64
    import os
    import subprocess
    import sys

    sink, _recorder = _durable_sink(tmp_path)
    monkeypatch.setattr(sink, "_generator_source_identity", lambda: ("a" * 40, {}))
    original_popen = subprocess.Popen
    observed = {}
    sentinel = "SYNTHETIC-PRIVATE-REVISION-AND-ERROR"
    script = '''
import sys
from types import SimpleNamespace
from career_automation import candidate_generation_worker as worker
from career_automation.candidate_application_factory import CandidateApplicationPackage

def generate(**arguments):
    for role in ("generation.inputs", "document.source_inputs", "document.cv.constraints",
                 "document.cv.source", "document.cv.final_pdf", "document.cover_letter.source",
                 "document.cover_letter.final_pdf", "form.answers"):
        arguments["revision_writer"](role=role, value=SENTINEL.encode(), media_type="text/plain")
        if FAIL:
            print("synthetic private worker diagnostic", file=sys.stderr)
            raise ValueError(SENTINEL)
    return CandidateApplicationPackage(source=SimpleNamespace(), artifacts=SimpleNamespace(),
                                       vacancy_requirements=())
worker.build_candidate_application_package = generate
raise SystemExit(worker.main())
'''.replace("SENTINEL", repr(sentinel)).replace("FAIL", repr(failure))

    def launch(command, **kwargs):
        if command == [sys.executable, "-m", "career_automation.candidate_generation_worker"]:
            # Keep the real parent transport, substitute only the corpus-dependent
            # generator inside the child. Paths are explicit since parent changes cwd.
            kwargs["env"]["PYTHONPATH"] = os.pathsep.join(
                [str(ROOT), str(ROOT.parents[1] / "src")]
            )
            observed["stdout"] = os.dup(kwargs["stdout"].fileno())
            observed["stderr"] = os.dup(kwargs["stderr"].fileno())
            return original_popen([sys.executable, "-c", script], **kwargs)
        return original_popen(command, **kwargs)

    monkeypatch.setattr(runner_module.subprocess, "Popen", launch)
    arguments = dict(
        decision_receipt={}, candidate_projection={}, job_key="synthetic", vacancy_sha256="a" * 64,
        source_url="https://example.test/job", role_title="Synthetic", company_name="Example",
        contact=CandidateContact(full_name="Alex Example", email="alex@example.test", phone=None,
                                city="London", record_id="synthetic", record_version=1,
                                provenance_sha256="a" * 64),
    )
    try:
        if failure:
            with pytest.raises(RuntimeError, match="^isolated candidate generator failed$"):
                sink.generate_candidate_application(**arguments)
            assert sink.authority is None
        else:
            assert type(sink.generate_candidate_application(**arguments)) is CandidateApplicationPackage
            assert sink.authority is not None
        durable = sink._verified_durable_revisions()
        assert len(durable) == (1 if failure else 9)
        assert durable[0].value == sentinel.encode()
        if failure:
            diagnostic_rows = [
                row
                for row in _recorder.attempt._objects(_recorder.attempt._events())
                if row.role == "generation.worker.stderr"
            ]
            assert len(diagnostic_rows) == 1
            diagnostic = _recorder.attempt.read_artifact(diagnostic_rows[0])
            assert b"synthetic private worker diagnostic" in diagnostic
            assert sentinel.encode() in diagnostic
        for channel, descriptor in observed.items():
            os.lseek(descriptor, 0, os.SEEK_SET)
            data = os.read(descriptor, 65536)
            assert base64.b64encode(sentinel.encode()) not in data
            if channel == "stderr":
                assert (sentinel.encode() in data) is failure
            else:
                assert sentinel.encode() not in data
                message = json.loads(data)
                assert message["kind"] == ("failure" if failure else "result")
    finally:
        for descriptor in observed.values():
            os.close(descriptor)


def test_private_worker_diagnostic_is_hash_only_when_archive_safety_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    from career_automation.application_archive import ApplicationArchiveError

    sink, recorder = _durable_sink(tmp_path)
    diagnostic = b"synthetic diagnostic rejected by the archive safety scanner"

    def reject_diagnostic(_value: bytes, _media_type: str) -> None:
        raise ApplicationArchiveError("secret-like value cannot be archived")

    monkeypatch.setattr(runner_module, "_scan_secret_bytes", reject_diagnostic)
    sink._archive_worker_diagnostics(io.BytesIO(diagnostic), exit_code=2)

    rows = recorder.attempt._objects(recorder.attempt._events())
    assert not any(row.role == "generation.worker.stderr" for row in rows)
    receipts = [
        row for row in rows if row.role == "generation.worker.stderr_receipt"
    ]
    assert len(receipts) == 1
    receipt = json.loads(recorder.attempt.read_artifact(receipts[0]))
    assert receipt["content_state"] == "withheld_secret_like"
    assert receipt["byte_length"] == len(diagnostic)
    assert receipt["content_sha256"] == hashlib.sha256(diagnostic).hexdigest()
    assert diagnostic.decode() not in json.dumps(receipt)


@pytest.mark.parametrize("binding", [None, "1", "invalid", "9" * 5000])
def test_private_worker_rejects_absent_or_invalid_channel_without_traceback(binding) -> None:
    import os
    import subprocess
    import sys

    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT.parents[1] / "src")])
    environment.pop("JAA_GENERATION_OUTPUT_FD", None)
    if binding is not None:
        environment["JAA_GENERATION_OUTPUT_FD"] = binding
    result = subprocess.run(
        [sys.executable, "-m", "career_automation.candidate_generation_worker"],
        input="{}", text=True, capture_output=True, env=environment,
    )
    assert result.returncode == 2
    assert result.stderr == ""
    assert json.loads(result.stdout)["kind"] == "failure"
