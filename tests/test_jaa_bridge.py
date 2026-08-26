from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import builtins
from dataclasses import replace
from pathlib import Path

import pytest

import market_aligner.applications.jaa as jaa_module

from market_aligner.applications.jaa import (
    ATSForensicRecorder,
    ApplicationSource,
    AtsFieldOption,
    AtsFixturePreSubmitAuthority,
    AtsFormInventory,
    AtsObservationAuthority,
    AtsObservedField,
    FixtureCaptureBackend,
    SanityReviewReceipt,
    canonical_json,
    capture_or_recover,
    compile_fixture_pre_submit_plan,
    execute_fixture_pre_submit_or_recover,
    list_canary_learning_events,
    load_forensic_receipt,
    observe_ats_form_or_recover,
    record_canary_learning_event,
    sha256,
    verify_and_consume_market_observation_acceptance,
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


def observation_authority(
    value: ApplicationSource,
    *,
    url: str = "https://localhost/fixture-ats",
    state: str = "accepted",
    local_fixture_only: bool = True,
) -> AtsObservationAuthority:
    fields = {
        "schema_version": "market-aligner.ats-observation-authority.v1",
        "job_key": value.job_key,
        "application_url": url,
        "timeout_ms": 2_000,
        "max_network_events": 8,
        "max_snapshot_bytes": 65_536,
        "authority_state": state,
        "local_fixture_only": local_fixture_only,
        "diagnostic_only": True,
        "raw_payloads_persisted": False,
        "identity_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    return AtsObservationAuthority(
        **fields,
        authority_sha256=sha256(canonical_json(fields).encode()),
    )


def public_observation_request(
    value: ApplicationSource,
    *,
    url: str = "https://jobs.example.test/apply/1000001",
) -> AtsObservationAuthority:
    return observation_authority(
        value,
        url=url,
        state="pending",
        local_fixture_only=False,
    )


def observation_signing_key(tmp_path: Path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    external_root = tmp_path / "external-authority"
    external_root.mkdir(mode=0o700)
    public_path = external_root / "test-observation-public.pem"
    public_path.write_bytes(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    public_path.chmod(0o644)
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    monkeypatch.setattr(jaa_module, "MARKET_OBSERVATION_KEY_ID", "market-observation-test-key")
    monkeypatch.setattr(
        jaa_module,
        "MARKET_OBSERVATION_PUBLIC_DER_SHA256",
        sha256(public_der),
    )
    monkeypatch.setattr(jaa_module, "_utc_now", lambda: "2026-08-27T12:00:00Z")
    return private_key, public_path, external_root


def write_signed_observation_acceptance(
    external_root: Path,
    private_key,
    authority: AtsObservationAuthority,
    *,
    consumption_root: Path,
    acceptance_id: str = "observation-acceptance-001",
    nonce: str = "1" * 64,
    key_id: str = "market-observation-test-key",
    not_before: str = "2026-08-27T11:59:00Z",
    expires_at: str = "2026-08-27T12:05:00Z",
    signing_key=None,
) -> tuple[Path, dict[str, object]]:
    if not consumption_root.exists():
        consumption_root.mkdir(mode=0o700)
    consumption_store = consumption_root / "observation-acceptance-consumptions"
    if not consumption_store.exists():
        consumption_store.mkdir(mode=0o700)
    fields = {
        "schema_version": "market-aligner.ats-observation-acceptance.v1",
        "acceptance_id": acceptance_id,
        "nonce": nonce,
        "request_sha256": authority.authority_sha256,
        "consumption_root_sha256": jaa_module.market_observation_consumption_root_sha256(
            consumption_root
        ),
        "job_key": authority.job_key,
        "application_url": authority.application_url,
        "timeout_ms": authority.timeout_ms,
        "max_network_events": authority.max_network_events,
        "max_snapshot_bytes": authority.max_snapshot_bytes,
        "not_before": not_before,
        "expires_at": expires_at,
        "key_id": key_id,
        "read_only_navigation": True,
        "sanitized_hash_only_evidence": True,
        "login_authority": False,
        "cookie_authority": False,
        "identity_authority": False,
        "vault_authority": False,
        "fill_authority": False,
        "upload_authority": False,
        "click_authority": False,
        "submission_authority": False,
    }
    signature = (signing_key or private_key).sign(canonical_json(fields).encode())
    document = fields | {"signature_b64": base64.b64encode(signature).decode("ascii")}
    document["envelope_sha256"] = sha256(canonical_json(document).encode())
    acceptances = external_root / "acceptances"
    acceptances.mkdir(mode=0o700, exist_ok=True)
    acceptances.chmod(0o700)
    path = acceptances / f"{acceptance_id}.json"
    path.write_bytes((canonical_json(document) + "\n").encode())
    path.chmod(0o600)
    return path, document


def pre_submit_authority(observation, values: dict[str, bytes]) -> AtsFixturePreSubmitAuthority:
    assert observation.inventory is not None
    plan = compile_fixture_pre_submit_plan(observation, values)
    fields = {
        "schema_version": "market-aligner.ats-fixture-pre-submit-authority.v1",
        "job_key": observation.job_key,
        "application_url": observation.final_application_url,
        "observation_manifest_sha256": observation.receipt.manifest_sha256,
        "inventory_sha256": observation.inventory.content_sha256,
        "plan_sha256": sha256(canonical_json({"schema_version": "market-aligner.ats-pre-submit-plan.v1", "fields": [field.document() for field in plan]}).encode()),
        "local_fixture_only": True,
        "synthetic_values_only": True,
        "identity_authority": False,
        "vault_authority": False,
        "submission_authority": False,
    }
    return AtsFixturePreSubmitAuthority(
        **fields,
        authority_sha256=sha256(canonical_json(fields).encode()),
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


def test_ats_form_inventory_is_sanitized_content_addressed_and_default_off() -> None:
    inventory = AtsFormInventory(
        provider="greenhouse",
        application_url="https://job-boards.greenhouse.io/example/jobs/1234567",
        captured_at="2026-08-27T12:00:00Z",
        page_snapshot_sha256="a" * 64,
        screenshot_sha256s=("b" * 64,),
        fields=(
            AtsObservedField("full_name", "text", "Full name", True, True),
            AtsObservedField(
                "work_mode", "select", "Work mode", False, True,
                options=(AtsFieldOption("remote", "Remote"),),
            ),
            AtsObservedField(
                "trap", "hidden", "Hidden verification", False, False,
                automation_role="honeypot",
            ),
        ),
    )
    document = inventory.document()
    assert document["diagnostic_only"] is True
    assert document["raw_payloads_persisted"] is False
    assert all(document[name] is False for name in ("identity_authority", "release_authority", "submission_authority"))
    assert "current_value" not in canonical_json(document)
    assert inventory.content_sha256 == sha256(canonical_json(document).encode())


@pytest.mark.parametrize(
    "field",
    (
        AtsObservedField("full_name", "text", "Full name", True, True),
        AtsObservedField("trap", "hidden", "Hidden verification", False, False, automation_role="honeypot"),
    ),
)
def test_ats_inventory_shape_refuses_duplicate_fields_and_unsafe_screenshot_identity(field: AtsObservedField) -> None:
    with pytest.raises(ValueError, match="field IDs"):
        AtsFormInventory(
            provider="fixture", application_url="https://jobs.example.test/application",
            captured_at="2026-08-27T12:00:00Z", page_snapshot_sha256="a" * 64,
            screenshot_sha256s=(), fields=(field, field),
        )
    with pytest.raises(ValueError, match="screenshot hashes"):
        AtsFormInventory(
            provider="fixture", application_url="https://jobs.example.test/application",
            captured_at="2026-08-27T12:00:00Z", page_snapshot_sha256="a" * 64,
            screenshot_sha256s=("b" * 64, "b" * 64), fields=(field,),
        )


def test_real_playwright_local_fixture_observation_is_sanitized_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("playwright.sync_api")
    application = source()
    secret = "secret@example.test"
    html = f"""<!doctype html><form id='application'>
      <label for='name'>Full name</label><input id='name' required value='{secret}'>
      <label for='team'>Team</label><select id='team' multiple><option value='eng'>Engineering</option><option value='ops'>Operations</option></select>
      <input id='trap' name='trap' type='hidden' value='private-token'>
      <input id='managed' name='managed' readonly value='provider-managed'>
      <script>
        for (const event of ['click', 'input', 'change', 'submit']) document.addEventListener(event, () => fetch('/interaction-' + event));
      </script>
    </form>"""
    kwargs = {
        "root": tmp_path / "forensics",
        "attempt_id": "attempt-observe-0001",
        "application_id": "application-observe-0001",
        "source": application,
        "sanity": sanity(application),
        "ats_name": "fixture",
        "authority": observation_authority(application),
        "captured_at": "2026-08-27T12:00:00Z",
        "fixture_html": html,
    }
    observed = observe_ats_form_or_recover(**kwargs)
    assert observed.receipt.outcome == "prepared"
    assert observed.inventory is not None
    assert {field.field_id: field for field in observed.inventory.fields}["team"].multiple is True
    assert {field.field_id: field for field in observed.inventory.fields}["trap"].automation_role == "honeypot"
    assert {field.field_id: field for field in observed.inventory.fields}["managed"].automation_role == "provider_managed"
    assert observed.network_event_count == 1
    manifest = (tmp_path / "forensics" / "manifests" / "attempt-observe-0001.json").read_text()
    assert secret not in manifest
    assert "private-token" not in manifest
    assert "current_value" not in manifest
    import playwright.sync_api
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: (_ for _ in ()).throw(AssertionError("replay launched browser")))
    assert observe_ats_form_or_recover(**kwargs) == observed


def test_unaccepted_public_observation_refuses_before_playwright_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = source()
    authority = observation_authority(
        application,
        url="https://jobs.example.test/role",
        state="pending",
        local_fixture_only=False,
    )
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise AssertionError("unaccepted authority imported Playwright")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(PermissionError, match="external verified operator capability"):
        observe_ats_form_or_recover(
            root=tmp_path / "forensics", attempt_id="attempt-observe-0002",
            application_id="application-observe-0002", source=application,
            sanity=sanity(application), ats_name="fixture", authority=authority,
            captured_at="2026-08-27T12:00:00Z", fixture_html="<form><input id='x'></form>",
        )


def test_forged_accepted_public_observation_refuses_before_playwright_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = source()
    authority = observation_authority(
        application,
        url="https://jobs.example.test/role",
        state="accepted",
        local_fixture_only=False,
    )
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise AssertionError("forged public acceptance imported Playwright")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(PermissionError, match="external verified operator capability"):
        observe_ats_form_or_recover(
            root=tmp_path / "forensics", attempt_id="attempt-observe-0003",
            application_id="application-observe-0003", source=application,
            sanity=sanity(application), ats_name="fixture", authority=authority,
            captured_at="2026-08-27T12:00:00Z", fixture_html="<form><input id='x'></form>",
        )


def test_real_playwright_malicious_fixture_is_terminally_blocked_without_interaction(
    tmp_path: Path
) -> None:
    pytest.importorskip("playwright.sync_api")
    application = source()
    secret = "private@example.test"
    html = f"""<!doctype html><form><input id='name' value='{secret}'><script>
      const input = document.querySelector('#name');
      for (const action of [
        () => input.value = 'changed', () => input.click(), () => document.forms[0].submit(),
        () => fetch('/escaped')
      ]) {{ try {{ action(); }} catch (_error) {{}} }}
    </script></form>"""
    observed = observe_ats_form_or_recover(
        root=tmp_path / "forensics", attempt_id="attempt-observe-malicious",
        application_id="application-observe-malicious", source=application,
        sanity=sanity(application), ats_name="fixture", authority=observation_authority(application),
        captured_at="2026-08-27T12:00:00Z", fixture_html=html,
    )
    assert (observed.receipt.outcome, observed.receipt.failure_class) == (
        "blocked", "read_only_interaction_attempted"
    )
    assert observed.inventory is None
    assert observed.network_event_count == 1
    manifest = (tmp_path / "forensics" / "manifests" / "attempt-observe-malicious.json").read_text()
    assert secret not in manifest
    assert "changed" not in manifest


def test_real_playwright_fixture_pre_submit_maps_fills_uploads_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("playwright.sync_api")
    application = source()
    html = """<form><input id='name' required><textarea id='note'></textarea><select id='team'><option value='eng'>Engineering</option></select><input name='work' type='radio' value='remote'><input name='work' type='radio' value='office'><input name='consent' type='checkbox' value='yes'><input id='cv' type='file' required><button type='submit'>Submit</button></form>"""
    observation = observe_ats_form_or_recover(
        root=tmp_path / "forensics", attempt_id="attempt-pre-submit-observe",
        application_id="application-pre-submit-observe", source=application,
        sanity=sanity(application), ats_name="fixture", authority=observation_authority(application),
        captured_at="2026-08-27T12:00:00Z", fixture_html=html,
    )
    values = {"name": b"Synthetic User", "note": b"fixture note", "team": b"eng", "work": b"remote", "consent": b"yes", "cv": b"synthetic fixture document"}
    kwargs = {
        "root": tmp_path / "forensics", "attempt_id": "attempt-pre-submit-0001",
        "application_id": "application-pre-submit-0001", "observation": observation,
        "authority": pre_submit_authority(observation, values), "values": values,
        "fixture_html": html,
    }
    with pytest.raises(RuntimeError, match="pre-publication fixture crash"):
        execute_fixture_pre_submit_or_recover(**kwargs, injected_crash_after_action=1)
    assert not (tmp_path / "forensics" / "manifests" / "attempt-pre-submit-0001.json").exists()
    receipt = execute_fixture_pre_submit_or_recover(**kwargs)
    assert (receipt.outcome, receipt.failure_class) == ("prepared", None)
    manifest = (tmp_path / "forensics" / "manifests" / "attempt-pre-submit-0001.json").read_text()
    assert "Synthetic User" not in manifest
    assert "synthetic fixture document" not in manifest
    import playwright.sync_api
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: (_ for _ in ()).throw(AssertionError("pre-submit replay launched browser")))
    assert execute_fixture_pre_submit_or_recover(**kwargs) == receipt


@pytest.mark.parametrize(
    ("html", "failure"),
    (
        ("<form><input id='password' type='password'></form>", "identity_required"),
        ("<form><input id='name'><iframe title='captcha challenge'></iframe></form>", "human_verification"),
    ),
)
def test_real_playwright_local_fixture_terminal_blocks(
    tmp_path: Path, html: str, failure: str
) -> None:
    pytest.importorskip("playwright.sync_api")
    application = source()
    observed = observe_ats_form_or_recover(
        root=tmp_path / "forensics", attempt_id=f"attempt-observe-{failure}",
        application_id=f"application-observe-{failure}", source=application,
        sanity=sanity(application), ats_name="fixture", authority=observation_authority(application),
        captured_at="2026-08-27T12:00:00Z", fixture_html=html,
    )
    assert (observed.receipt.outcome, observed.receipt.failure_class) == ("blocked", failure)
    assert observed.inventory is None


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


def test_signed_observation_acceptance_consumes_once_and_replays_exactly(tmp_path, monkeypatch):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, envelope = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )

    first = verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_path,
        consumption_root=runtime_root,
    )
    receipt_path = runtime_root / "observation-acceptance-consumptions" / f"{envelope['nonce']}.json"
    original = receipt_path.read_bytes()
    original_mtime = receipt_path.stat().st_mtime_ns
    monkeypatch.setattr(jaa_module, "_utc_now", lambda: "2026-08-28T12:00:00Z")
    replay = verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_path,
        consumption_root=runtime_root,
    )

    assert replay == first
    assert receipt_path.read_bytes() == original
    assert receipt_path.stat().st_mtime_ns == original_mtime
    assert first.request_sha256 == authority.authority_sha256
    assert first.envelope_sha256 == envelope["envelope_sha256"]
    assert first.signature_sha256 == sha256(base64.b64decode(envelope["signature_b64"]))
    assert first.consumption_root_sha256 == envelope["consumption_root_sha256"]
    assert first.not_before == envelope["not_before"]
    assert first.expires_at == envelope["expires_at"]
    assert first.key_id == "market-observation-test-key"
    assert first.public_der_sha256 == jaa_module.MARKET_OBSERVATION_PUBLIC_DER_SHA256
    assert first.diagnostic_only is True
    assert first.raw_payloads_persisted is False
    assert first.identity_authority is False
    assert first.vault_authority is False
    assert first.release_authority is False
    assert first.submission_authority is False
    assert len(list(receipt_path.parent.iterdir())) == 1


@pytest.mark.parametrize("attack", ["forged_self_hash", "unknown_key", "wrong_target", "expired", "future"])
def test_signed_observation_acceptance_refuses_invalid_authority(tmp_path, monkeypatch, attack):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    call_authority = authority
    runtime_root = tmp_path / "runtime"
    kwargs = {}
    if attack == "forged_self_hash":
        kwargs["signing_key"] = Ed25519PrivateKey.generate()
    elif attack == "unknown_key":
        kwargs["key_id"] = "unknown-observation-key"
    elif attack == "wrong_target":
        call_authority = public_observation_request(
            source(),
            url="https://jobs.example.test/apply/another-target",
        )
    elif attack == "expired":
        kwargs.update(not_before="2026-08-27T11:00:00Z", expires_at="2026-08-27T11:59:59Z")
    elif attack == "future":
        kwargs.update(not_before="2026-08-27T12:00:01Z", expires_at="2026-08-27T13:00:00Z")
    envelope_path, _ = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
        **kwargs,
    )

    with pytest.raises(ValueError):
        verify_and_consume_market_observation_acceptance(
            call_authority,
            envelope_path=envelope_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )
    assert not list((runtime_root / "observation-acceptance-consumptions").iterdir())


def test_signed_observation_acceptance_refuses_duplicate_nonce_drift(tmp_path, monkeypatch):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    first_authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    first_path, first_envelope = write_signed_observation_acceptance(
        external_root,
        private_key,
        first_authority,
        consumption_root=runtime_root,
        nonce="2" * 64,
    )
    verify_and_consume_market_observation_acceptance(
        first_authority,
        envelope_path=first_path,
        public_key_path=public_path,
        consumption_root=runtime_root,
    )
    receipt_path = runtime_root / "observation-acceptance-consumptions" / f"{first_envelope['nonce']}.json"
    original = receipt_path.read_bytes()
    drifted_authority = public_observation_request(
        source(),
        url="https://jobs.example.test/apply/another-target",
    )
    drifted_path, _ = write_signed_observation_acceptance(
        external_root,
        private_key,
        drifted_authority,
        consumption_root=runtime_root,
        acceptance_id="observation-acceptance-002",
        nonce="2" * 64,
    )

    with pytest.raises(ValueError, match="different evidence"):
        verify_and_consume_market_observation_acceptance(
            drifted_authority,
            envelope_path=drifted_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )
    assert receipt_path.read_bytes() == original


def test_signed_observation_acceptance_cannot_switch_replay_root(tmp_path, monkeypatch):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    first_root = tmp_path / "runtime-one"
    second_root = tmp_path / "runtime-two"
    envelope_path, _ = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=first_root,
        nonce="3" * 64,
    )
    verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_path,
        consumption_root=first_root,
    )
    second_root.mkdir(mode=0o700)
    (second_root / "observation-acceptance-consumptions").mkdir(mode=0o700)

    with pytest.raises(ValueError, match="replay domain"):
        verify_and_consume_market_observation_acceptance(
            authority,
            envelope_path=envelope_path,
            public_key_path=public_path,
            consumption_root=second_root,
        )
    assert not list((second_root / "observation-acceptance-consumptions").iterdir())


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "mode"])
def test_signed_observation_acceptance_refuses_unsafe_envelope(tmp_path, monkeypatch, attack):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, _ = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )
    attacked_path = envelope_path
    if attack == "symlink":
        attacked_path = envelope_path.with_name("acceptance-symlink.json")
        attacked_path.symlink_to(envelope_path.name)
    elif attack == "hardlink":
        attacked_path = envelope_path.with_name("acceptance-hardlink.json")
        os.link(envelope_path, attacked_path)
    else:
        envelope_path.chmod(0o644)

    with pytest.raises(ValueError):
        verify_and_consume_market_observation_acceptance(
            authority,
            envelope_path=attacked_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )
    assert not list((runtime_root / "observation-acceptance-consumptions").iterdir())


@pytest.mark.parametrize("attack", ["root_symlink", "root_mode"])
def test_signed_observation_acceptance_refuses_unsafe_consumption_root(tmp_path, monkeypatch, attack):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, _ = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )
    if attack == "root_symlink":
        real_root = tmp_path / "real-runtime"
        runtime_root.rename(real_root)
        runtime_root.symlink_to(real_root, target_is_directory=True)
    else:
        runtime_root.chmod(0o755)

    with pytest.raises(ValueError):
        verify_and_consume_market_observation_acceptance(
            authority,
            envelope_path=envelope_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )


@pytest.mark.parametrize("attack", ["hardlink", "mode", "root_substitution", "store_substitution"])
def test_signed_observation_acceptance_refuses_consumption_evidence_drift(tmp_path, monkeypatch, attack):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, envelope = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )
    verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_path,
        consumption_root=runtime_root,
    )
    receipt_path = runtime_root / "observation-acceptance-consumptions" / f"{envelope['nonce']}.json"
    if attack == "hardlink":
        os.link(receipt_path, receipt_path.with_name("receipt-hardlink.json"))
    elif attack == "mode":
        receipt_path.chmod(0o644)
    elif attack == "root_substitution":
        runtime_root.rename(tmp_path / "original-runtime")
        runtime_root.mkdir(mode=0o700)
        (runtime_root / "observation-acceptance-consumptions").mkdir(mode=0o700)
    else:
        store = runtime_root / "observation-acceptance-consumptions"
        store.rename(runtime_root / "original-observation-acceptance-consumptions")
        store.mkdir(mode=0o700)

    with pytest.raises(ValueError):
        verify_and_consume_market_observation_acceptance(
            authority,
            envelope_path=envelope_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )


def test_signed_observation_acceptance_requires_exact_authority_type(tmp_path, monkeypatch):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, _ = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )

    class DerivedAuthority(AtsObservationAuthority):
        pass

    derived = DerivedAuthority(**authority.__dict__)
    with pytest.raises(TypeError, match="canonical authority type"):
        verify_and_consume_market_observation_acceptance(
            derived,
            envelope_path=envelope_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )
    assert not list((runtime_root / "observation-acceptance-consumptions").iterdir())


def test_signed_observation_acceptance_recovers_crash_publish_link(tmp_path, monkeypatch):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, envelope = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )
    original = verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_path,
        consumption_root=runtime_root,
    )
    receipt_path = runtime_root / "observation-acceptance-consumptions" / f"{envelope['nonce']}.json"
    crash_link = receipt_path.with_name(f".{receipt_path.name}.{'a' * 32}.tmp")
    os.link(receipt_path, crash_link)
    assert receipt_path.stat().st_nlink == 2

    recovered = verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_path,
        consumption_root=runtime_root,
    )

    assert recovered == original
    assert receipt_path.stat().st_nlink == 1
    assert not crash_link.exists()


def test_signed_observation_acceptance_parent_swap_refuses_before_publication(tmp_path, monkeypatch):
    private_key, public_path, external_root = observation_signing_key(tmp_path, monkeypatch)
    authority = public_observation_request(source())
    runtime_root = tmp_path / "runtime"
    envelope_path, envelope = write_signed_observation_acceptance(
        external_root,
        private_key,
        authority,
        consumption_root=runtime_root,
    )
    original_writer = jaa_module._write_acceptance_once

    def swap_parent_then_write(store, name, data, *, prepublish_check):
        original_parent = envelope_path.parent.with_name("acceptances-original")
        envelope_path.parent.rename(original_parent)
        envelope_path.parent.mkdir(mode=0o700)
        return original_writer(
            store,
            name,
            data,
            prepublish_check=prepublish_check,
        )

    monkeypatch.setattr(jaa_module, "_write_acceptance_once", swap_parent_then_write)
    with pytest.raises(ValueError, match="parent path changed"):
        verify_and_consume_market_observation_acceptance(
            authority,
            envelope_path=envelope_path,
            public_key_path=public_path,
            consumption_root=runtime_root,
        )
    receipts = runtime_root / "observation-acceptance-consumptions"
    assert not (receipts / f"{envelope['nonce']}.json").exists()
    assert not list(receipts.glob("*.tmp"))
