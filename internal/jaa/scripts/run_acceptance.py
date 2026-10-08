#!/usr/bin/env python3
"""Run commercial acceptance from portable private runtime configuration."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from acceptance_runtime import RuntimeConfigurationError, default_config_path, load_runtime_config


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parents[1]
OUTPUT_PARENT = Path("/tmp")

CURRENT_MVP_FUNCTIONAL_TESTS = (
    "test_candidate_release_gate.py::test_candidate_gate_rejects_pdf_or_repository_drift",
    "test_candidate_release_gate.py::test_durable_authority_rehashes_exact_decision_projection_and_snapshot",
    "test_candidate_release_gate.py::test_candidate_gate_issues_consumes_and_reverifies_exact_inputs",
    "test_candidate_release_gate.py::test_candidate_gate_reauthenticates_durable_sources_before_consumption",
    "test_jaa11_live_canary_fixture_dry_run_negative_controls.py::test_unavailable_or_ambiguous_authority_fails_closed",
    "test_jaa11_live_canary_fixture_dry_run_negative_controls.py::test_result_cannot_open_any_external_boundary",
    "test_production_ats_executor.py::test_human_verification_is_archived_and_never_clicked",
    "test_production_ats_executor.py::test_dormant_invisible_recaptcha_widget_is_not_a_boundary",
    "test_production_ats_executor.py::test_crash_after_click_intent_recovers_without_duplicate_submit",
    "test_production_ats_executor.py::test_post_intent_gmail_match_resolves_success_without_click_replay",
    "test_production_ats_executor.py::test_url_only_confirmation_is_indeterminate_and_archived",
    "test_production_ats_executor.py::test_exact_receipt_sanity_archive_and_upload_gates_run_twice",
    "test_production_ats_executor.py::test_greenhouse_authority_rejects_nonofficial_or_mismatched_routes",
    "test_jaa09_negative_controls.py::test_fixture_refuses_non_loopback_bind_or_host_header",
    "test_jaa09_negative_controls.py::test_fixture_refuses_non_loopback_origin_header",
    "test_jaa09_negative_controls.py::test_duplicate_submit_and_second_review_produce_no_second_receipt",
    "test_jaa09_negative_controls.py::test_concurrent_nonce_replay_produces_exactly_one_receipt",
    "test_jaa09_negative_controls.py::test_interruption_after_click_recovers_receipt_without_second_submit",
    "test_jaa09_negative_controls.py::test_archive_is_reverified_after_prefill_and_immediately_before_click",
)
CURRENT_MVP_NATIVE_TEST = (
    "test_ma_native_browser_diagnostic.py::"
    "test_native_prepare_release_one_call_local_diagnostic"
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path, help="explicit private config path")
    result.add_argument(
        "--scope",
        choices=("historical", "current-greenhouse-mvp"),
        default="historical",
        help="run the strict historical acceptance or bounded current Greenhouse scope",
    )
    return result


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_output(*arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(PROJECT_ROOT), *arguments),
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError("unable to bind current project Git state")
    return completed.stdout


def _git_branch() -> str | None:
    completed = subprocess.run(
        (
            "git",
            "-C",
            str(PROJECT_ROOT),
            "symbolic-ref",
            "--short",
            "--quiet",
            "HEAD",
        ),
        capture_output=True,
        check=False,
    )
    if completed.returncode == 1:
        return None
    if completed.returncode != 0:
        raise RuntimeError("unable to bind current project Git branch")
    branch = completed.stdout.decode().strip()
    if not branch:
        raise RuntimeError("Git returned an empty symbolic branch name")
    return branch


def _execution_binding() -> dict[str, object]:
    git_root = Path(_git_output("rev-parse", "--show-toplevel").decode().strip()).resolve()
    if git_root != PROJECT_ROOT.resolve():
        raise RuntimeError("acceptance must run from the registered project Git root")
    untracked = _git_output("ls-files", "--others", "--exclude-standard", "-z")
    if untracked:
        raise RuntimeError("untracked project files prevent exact source binding")
    head = _git_output("rev-parse", "HEAD").decode().strip()
    branch = _git_branch()
    status = _git_output("status", "--porcelain=v1", "-z")
    tracked_diff = _git_output("diff", "--binary", "HEAD", "--")
    source = {
        "git_root": str(git_root),
        "branch": branch,
        "head": head,
        "status_sha256": _digest(status),
        "tracked_diff_sha256": _digest(tracked_diff),
    }
    source["tree_binding_sha256"] = _digest(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    )
    executable = Path(sys.executable)
    codex = shutil.which("codex")
    if codex is None:
        raise RuntimeError("Codex CLI is unavailable for the one-call native canary")
    distributions = sorted(
        (str(distribution.metadata.get("Name", "")), distribution.version)
        for distribution in importlib.metadata.distributions()
    )
    runtime = {
        "python_executable": str(executable),
        "python_executable_resolved": str(executable.resolve()),
        "python_executable_sha256": _digest(executable.resolve().read_bytes()),
        "python_version": sys.version,
        "python_prefix": sys.prefix,
        "python_base_prefix": sys.base_prefix,
        "installed_distributions_sha256": _digest(
            json.dumps(distributions, separators=(",", ":")).encode()
        ),
        "codex_cli": str(Path(codex).resolve()),
        "codex_cli_sha256": _digest(Path(codex).resolve().read_bytes()),
    }
    return {"source": source, "runtime": runtime}


def _write_private(path: Path, content: bytes, *, replace: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _write_result(root: Path, result: dict[str, object]) -> None:
    payload = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _write_private(root / "result.json", payload, replace=(root / "result.json").exists())


def _pytest_command(nodes: tuple[str, ...], basetemp: Path) -> tuple[str, ...]:
    return (
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--basetemp",
        str(basetemp),
        *nodes,
    )


def _native_result(root: Path) -> dict[str, object]:
    candidates = tuple(root.rglob("safe-result.json"))
    if len(candidates) != 1:
        raise RuntimeError("native canary did not produce one unambiguous safe result")
    result_path = candidates[0]
    if stat.S_IMODE(result_path.stat().st_mode) != 0o600:
        raise RuntimeError("native canary result is not private mode 0600")
    document = json.loads(result_path.read_text(encoding="utf-8"))
    fields = (
        "status",
        "attempt_id",
        "provider_dispatches",
        "provider_responses",
        "provider_response_capture_status",
        "provider_response_sha256",
        "sanity_receipt_sha256",
        "native_fill_returned",
        "prepared_returned",
        "attempt_finalized",
        "external_network_requests",
        "intercepted_post_attempts",
        "external_submission",
        "terminal_archive_roles",
        "default_production_verifier_rejected_actual_diagnostic_receipt",
    )
    return {field: document.get(field) for field in fields}


def _native_result_is_accepted(document: dict[str, object]) -> bool:
    roles = document.get("terminal_archive_roles")
    return (
        document.get("status") == "prepared_no_submit"
        and isinstance(document.get("attempt_id"), str)
        and document.get("provider_dispatches") == 1
        and document.get("provider_responses") == 1
        and document.get("provider_response_capture_status") == "written"
        and isinstance(document.get("provider_response_sha256"), str)
        and isinstance(document.get("sanity_receipt_sha256"), str)
        and document.get("native_fill_returned") is True
        and document.get("prepared_returned") is True
        and document.get("attempt_finalized") is True
        and document.get("external_network_requests") == 0
        and document.get("intercepted_post_attempts") == 0
        and document.get("external_submission") == 0
        and isinstance(roles, list)
        and "submission.result" in roles
        and document.get("default_production_verifier_rejected_actual_diagnostic_receipt") is True
    )


def _run_current_greenhouse_mvp() -> int:
    output_root = Path(tempfile.mkdtemp(prefix="ma-current-greenhouse-mvp-", dir=OUTPUT_PARENT))
    output_root.chmod(0o700)
    if (
        output_root.is_symlink()
        or not output_root.is_dir()
        or stat.S_IMODE(output_root.stat().st_mode) != 0o700
        or output_root.resolve().parent != OUTPUT_PARENT.resolve()
    ):
        raise RuntimeError("current-MVP evidence directory is not a fresh private directory")

    offline_temp = output_root / "functional"
    native_temp = output_root / "native"
    offline_command = _pytest_command(CURRENT_MVP_FUNCTIONAL_TESTS, offline_temp)
    native_command = _pytest_command((CURRENT_MVP_NATIVE_TEST,), native_temp)
    pythonpath = os.pathsep.join((str(PROJECT_ROOT / "src"), str(ROOT)))
    offline_environment = os.environ.copy()
    offline_environment["PYTHONPATH"] = pythonpath
    offline_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    offline_environment.pop("MA_RUN_NATIVE_BROWSER_DIAGNOSTIC", None)
    native_environment = offline_environment.copy()
    native_environment["MA_RUN_NATIVE_BROWSER_DIAGNOSTIC"] = "1"

    result: dict[str, object] = {
        "schema_version": "market-aligner.current-greenhouse-mvp.v1",
        "scope": "current-greenhouse-mvp",
        "status": "running",
        "historical_certification": "unproven_not_run",
        "external_application": "not_performed",
        "release_claim": False,
        "evidence_directory": str(output_root),
        "commands": [],
    }
    _write_private(
        output_root / "argv.json",
        (
            json.dumps(
                {
                    "cwd": str(ROOT),
                    "pythonpath": pythonpath,
                    "environment_flags": {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "MA_RUN_NATIVE_BROWSER_DIAGNOSTIC": "1",
                    },
                    "commands": [list(offline_command), list(native_command)],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode(),
    )
    try:
        initial_binding = _execution_binding()
        result["source_runtime_binding_before"] = initial_binding
    except Exception as error:
        result.update(status="admission_failed", error_type=type(error).__name__)
        _write_result(output_root, result)
        print(json.dumps({"status": result["status"], "evidence_directory": str(output_root)}))
        return 2
    _write_result(output_root, result)

    commands = (
        ("functional", offline_command, offline_environment, offline_temp),
        ("native", native_command, native_environment, native_temp),
    )
    for stage, command, environment, basetemp in commands:
        if stage == "native":
            try:
                current_binding = _execution_binding()
            except Exception as error:
                result.update(status="pre_canary_binding_failed", error_type=type(error).__name__)
                _write_result(output_root, result)
                break
            if current_binding != initial_binding:
                result.update(status="source_or_runtime_changed_before_canary")
                result["source_runtime_binding_before_canary"] = current_binding
                _write_result(output_root, result)
                break
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            stdout = completed.stdout.encode("utf-8", errors="replace")
            stderr = completed.stderr.encode("utf-8", errors="replace")
            returncode: int | None = completed.returncode
            launch_error = None
        except OSError as error:
            stdout = b""
            stderr = f"{type(error).__name__}: {error}".encode("utf-8", errors="replace")
            returncode = None
            launch_error = type(error).__name__
        stdout_path = output_root / f"{stage}.stdout.log"
        stderr_path = output_root / f"{stage}.stderr.log"
        _write_private(stdout_path, stdout)
        _write_private(stderr_path, stderr)
        stage_record: dict[str, object] = {
            "stage": stage,
            "argv": list(command),
            "exit_code": returncode,
            "stdout_path": str(stdout_path),
            "stdout_sha256": _digest(stdout),
            "stderr_path": str(stderr_path),
            "stderr_sha256": _digest(stderr),
        }
        if launch_error is not None:
            stage_record["launch_error_type"] = launch_error
        if stage == "native" and returncode == 0:
            try:
                native_document = _native_result(basetemp)
                stage_record["native_result"] = native_document
                if not _native_result_is_accepted(native_document):
                    stage_record["evidence_validation"] = "failed"
            except Exception as error:
                stage_record["evidence_validation"] = "failed"
                stage_record["evidence_error_type"] = type(error).__name__
        result["commands"].append(stage_record)
        if returncode != 0:
            result["status"] = f"{stage}_checks_failed"
            _write_result(output_root, result)
            break
        if stage == "native" and stage_record.get("evidence_validation") == "failed":
            result["status"] = "native_evidence_failed"
            _write_result(output_root, result)
            break
        result["status"] = f"{stage}_checks_passed"
        _write_result(output_root, result)

    try:
        final_binding = _execution_binding()
        result["source_runtime_binding_after"] = final_binding
        if final_binding != initial_binding:
            result["status"] = "source_or_runtime_changed_during_acceptance"
    except Exception as error:
        result["status"] = "post_run_binding_failed"
        result["post_run_binding_error_type"] = type(error).__name__
    if result["status"] == "native_checks_passed":
        result["status"] = "current_functional_scope_pass_historical_unproven"
    _write_result(output_root, result)
    exit_code = 0 if result["status"] == "current_functional_scope_pass_historical_unproven" else 1
    print(
        json.dumps(
            {
                "scope": result["scope"],
                "status": result["status"],
                "historical_certification": result["historical_certification"],
                "external_application": result["external_application"],
                "release_claim": result["release_claim"],
                "evidence_directory": result["evidence_directory"],
                "exit_code": exit_code,
            },
            sort_keys=True,
        )
    )
    return exit_code


def main() -> int:
    args = parser().parse_args()
    if args.scope == "current-greenhouse-mvp":
        if args.config is not None:
            print("current-greenhouse-mvp: --config is only valid for historical acceptance", file=sys.stderr)
            return 2
        return _run_current_greenhouse_mvp()
    try:
        config = load_runtime_config(args.config if args.config is not None else default_config_path())
    except RuntimeConfigurationError as exc:
        print(f"commercial-acceptance: ERROR: {exc}", file=sys.stderr)
        return 2

    commands = (
        (sys.executable, "-m", "baseline_adoption.cli", "recertify-sources",
         "--source-root", config["original_source_root"], "--evidence-directory",
         config["recertification_evidence_directory"]),
        (sys.executable, "scripts/accept_jaa_01c.py"),
        (sys.executable, "-m", "pytest", "-q",
         "career_automation/test_jaa_01e_lifecycle_no_bypass.py"),
        (sys.executable, "scripts/reproduce_jaa01_terra_rejection.py"),
        (sys.executable, "-m", "pytest", "-q"),
    )
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
