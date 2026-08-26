from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from market_aligner.applications.jaa import (
    ATSForensicRecorder,
    ApplicationSource,
    FixtureCaptureBackend,
    SanityReviewReceipt,
    canonical_json,
    capture_or_recover,
    list_canary_learning_events,
    load_forensic_receipt,
    record_canary_learning_event,
    sha256,
    verify_canary_learning_event,
)
from market_aligner.cli import main as cli_main
from market_aligner.processing import eligibility_one
from market_aligner.service.api import MarketAlignerService


def source() -> ApplicationSource:
    values = {
        "profile_id": "prf_0123456789abcdef0123456789abcdef",
        "job_key": "greenhouse.1000001",
        "eligibility_receipt_sha256": "a" * 64,
        "fit_receipt_sha256": "b" * 64,
        "evidence_reference_sha256": "c" * 64,
        "contact_reference_sha256": "d" * 64,
    }
    return ApplicationSource(
        **values,
        source_sha256=hashlib.sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    )


def sanity(value: ApplicationSource) -> SanityReviewReceipt:
    fields = {
        "source_sha256": value.source_sha256,
        "artifact_set_sha256": "e" * 64,
        "backend": "fixture_capture",
        "model": "deterministic-v1",
        "verdict": "pass",
    }
    return SanityReviewReceipt(
        **fields,
        receipt_sha256=hashlib.sha256(
            json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    )


def test_prepared_replay_does_not_recapture(tmp_path: Path) -> None:
    calls: list[str] = []

    class Backend(FixtureCaptureBackend):
        def capture(self, request, recorder):
            calls.append(request.attempt_id)
            return super().capture(request, recorder)

    application = source()
    kwargs = {
        "root": tmp_path / "forensics",
        "attempt_id": "attempt-0001",
        "application_id": "application-0001",
        "source": application,
        "sanity": sanity(application),
        "ats_name": "fixture",
        "backend": Backend(),
    }
    assert capture_or_recover(**kwargs) == capture_or_recover(**kwargs)
    assert calls == ["attempt-0001"]


def test_unsupported_ats_blocks_without_submission(tmp_path: Path) -> None:
    application = source()
    receipt = capture_or_recover(
        root=tmp_path / "forensics",
        attempt_id="attempt-0002",
        application_id="application-0002",
        source=application,
        sanity=sanity(application),
        ats_name="unsupported",
    )
    assert (receipt.outcome, receipt.failure_class) == ("blocked", "unsupported_ats")
    assert receipt.document()["submission_authority"] is False


def test_binding_and_root_swap_refuse(tmp_path: Path) -> None:
    application = source()
    root = tmp_path / "forensics"
    receipt = capture_or_recover(
        root=root,
        attempt_id="attempt-0003",
        application_id="application-0003",
        source=application,
        sanity=sanity(application),
        ats_name="fixture",
    )
    with pytest.raises(ValueError):
        load_forensic_receipt(
            root,
            attempt_id=receipt.attempt_id,
            application_id="application-other",
            binding_sha256="0" * 64,
        )
    replaced = tmp_path / "replaced"
    root.rename(replaced)
    root.mkdir(mode=0o700)
    (root / "manifests").mkdir(mode=0o700)
    copied = root / "manifests" / f"{receipt.attempt_id}.json"
    copied.write_bytes((replaced / "manifests" / copied.name).read_bytes())
    copied.chmod(0o600)
    binding = json.loads(copied.read_text())["binding_sha256"]
    with pytest.raises(ValueError, match="binding differs"):
        load_forensic_receipt(
            root,
            attempt_id=receipt.attempt_id,
            application_id=receipt.application_id,
            binding_sha256=binding,
        )


def test_forensics_persists_no_raw_secret(tmp_path: Path) -> None:
    recorder = ATSForensicRecorder(
        tmp_path / "forensics",
        attempt_id="attempt-0004",
        application_id="application-0004",
        binding_sha256="f" * 64,
    )
    recorder.checkpoint("blocked")
    receipt = recorder.finalize(
        outcome="blocked", failure_class="identity_required"
    )
    evidence = tmp_path / "forensics" / "manifests" / f"{receipt.attempt_id}.json"
    assert "secret@example.test" not in evidence.read_text()


def test_learning_event_is_receipt_bound_idempotent_and_secret_free(tmp_path: Path) -> None:
    application = source()
    root = tmp_path / "forensics"
    receipt = capture_or_recover(root=root, attempt_id="attempt-learning-0001", application_id="application-learning-0001", source=application, sanity=sanity(application), ats_name="fixture")
    fields = {"recorded_at": "2026-08-27T12:00:00Z", "cycle_id": "cycle-learning-0001", "stage": "ats_preflight", "issue_code": "prepared", "summary": "observation_captured"}
    event = record_canary_learning_event(root, receipt, **fields)
    assert record_canary_learning_event(root, receipt, **fields) == event
    assert verify_canary_learning_event(root, event.event_sha256) == event
    assert list_canary_learning_events(root) == (event,)
    secret = "token=private-access-token"
    with pytest.raises(ValueError):
        record_canary_learning_event(root, receipt, **(fields | {"summary": secret}))
    assert all(secret.encode() not in path.read_bytes() for path in root.rglob("*") if path.is_file())


def test_learning_event_rejects_noncanonical_time_and_reconstructs_chronology(tmp_path: Path) -> None:
    application = source()
    root = tmp_path / "forensics"
    receipt = capture_or_recover(root=root, attempt_id="attempt-learning-0002", application_id="application-learning-0002", source=application, sanity=sanity(application), ats_name="fixture")
    fields = {"cycle_id": "cycle-learning-0002", "stage": "ats_preflight", "issue_code": "prepared", "summary": "observation_captured"}
    for value in ("2026-08-27T12:00:00+00:00", "2026-08-27T12:00:00", "2026-08-27T12:00:00.1234567Z"):
        with pytest.raises(ValueError):
            record_canary_learning_event(root, receipt, recorded_at=value, **fields)
    events = [record_canary_learning_event(root, receipt, recorded_at=f"2026-08-27T12:00:00.{index:06d}Z", **(fields | {"cycle_id": f"cycle-learning-{index:04d}"})) for index in range(8, 0, -1)]
    expected = tuple(sorted(events, key=lambda event: (event.recorded_at, event.event_sha256)))
    assert tuple(events) != expected
    assert list_canary_learning_events(root) == expected


def test_learning_event_refuses_every_contradictory_forensic_authority_before_publication(tmp_path: Path) -> None:
    application = source()
    root = tmp_path / "forensics"
    receipt = capture_or_recover(root=root, attempt_id="attempt-learning-0003", application_id="application-learning-0003", source=application, sanity=sanity(application), ats_name="fixture")
    manifest = root / "manifests" / f"{receipt.attempt_id}.json"
    original = manifest.read_bytes()
    document = json.loads(original)
    fields = {"recorded_at": "2026-08-27T12:00:00Z", "cycle_id": "cycle-learning-0003", "stage": "ats_preflight", "issue_code": "prepared", "summary": "observation_captured"}
    for name, contradictory in (("diagnostic_only", False), ("raw_payloads_persisted", True), ("identity_authority", True), ("release_authority", True), ("submission_authority", True)):
        changed = document | {name: contradictory}
        changed_bytes = (canonical_json(changed) + "\n").encode()
        forged = replace(receipt, manifest_sha256=sha256(changed_bytes), receipt_sha256="0" * 64)
        forged = replace(forged, receipt_sha256=sha256(canonical_json(forged.document() | {"receipt_sha256": None}).encode()))
        manifest.write_bytes(changed_bytes)
        with pytest.raises(ValueError, match="forensic receipt binding differs"):
            record_canary_learning_event(root, forged, **fields)
        assert not (root / "learning-events").exists()
        assert manifest.read_bytes() == changed_bytes
        manifest.write_bytes(original)
    assert manifest.read_bytes() == original


def test_installed_import_has_no_protected_dependencies() -> None:
    code = """import importlib.abc, sys
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] in {'playwright', 'requests', 'cryptography', 'career_automation'}:
            raise RuntimeError(name)
sys.meta_path.insert(0, Guard())
import market_aligner.applications.jaa
print('PASS')
"""
    root = Path(__file__).parents[1]
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root / "src")},
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr


def test_real_market_eligibility_receipt_flows_through_service_and_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The existing real FIT->eligibility fixture feeds the internal corridor."""
    fixture_path = Path(__file__).with_name("test_process_one.py")
    specification = importlib.util.spec_from_file_location("jaa_fixture", fixture_path)
    assert specification is not None and specification.loader is not None
    fixture_module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(fixture_module)
    fixture = fixture_module.EligibilityFixture(tmp_path)
    candidate = fixture.candidate_facts()
    candidate["authorised_jurisdictions"]["value"] = [
        {"refs": [fixture.ref("ev-de")], "value": "NL"}
    ]
    candidate["current_residence"]["value"] = "NL"
    candidate["maximum_years_required"]["value"] = 5.0
    vacancy = fixture.vacancy_facts()
    vacancy["minimum_years_required"]["value"] = 3.0
    payload = fixture.envelope(
        candidate_overrides={
            key: candidate[key]
            for key in (
                "authorised_jurisdictions",
                "current_residence",
                "maximum_years_required",
            )
        },
        vacancy_overrides={"minimum_years_required": vacancy["minimum_years_required"]},
    )
    envelope_name = fixture.stage(payload)
    receipt = eligibility_one(
        fixture.root,
        envelope_name,
        supplied_operation_id=payload["eligibility_operation_id"],
        supplied_fit_operation_id=payload["fit_operation_id"],
        supplied_config_path=fixture.resolved_config_path,
        supplied_profile_id=fixture_module._PROFILE_ID,
        supplied_job_key="board:42",
        supplied_track="backend",
    )
    references = {"evidence": "1" * 64, "contact": "2" * 64}
    direct = MarketAlignerService.prepare_internal_jaa(
        eligibility_receipt=receipt,
        evidence_reference_sha256=references["evidence"],
        contact_reference_sha256=references["contact"],
        forensic_root=tmp_path / "service-forensics",
        attempt_id="attempt-service-0001",
        application_id="application-service-0001",
    )
    assert direct["status"] == "prepared"
    receipt_path = tmp_path / "eligibility.json"
    receipt_path.write_bytes(receipt)
    assert cli_main([
        "applications", "--eligibility-receipt", str(receipt_path),
        "--evidence-reference-sha256", references["evidence"],
        "--contact-reference-sha256", references["contact"],
        "--forensic-root", str(tmp_path / "cli-forensics"),
        "--attempt-id", "attempt-cli-0001",
        "--application-id", "application-cli-0001",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "prepared"
