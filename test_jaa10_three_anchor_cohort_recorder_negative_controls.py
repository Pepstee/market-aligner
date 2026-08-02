"""Adversarial controls for the JAA-10 three-anchor cohort recorder."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation import external_time_attestation as external_time
from career_automation import three_anchor_cohort_recorder as recorder_module
from career_automation.external_time_attestation import ExternalTimeStatus
from career_automation.three_anchor_cohort_recorder import (
    CohortJournalIntegrityError,
    CohortStateError,
    FrozenIdentityDriftError,
)
from test_jaa10_three_anchor_cohort_recorder import (
    EMPLOYERS,
    _admit_obs1_a1,
    _bind_policy,
    _canonical,
    _complete_unit,
    _digest,
    _fake_verifier,
    _identity,
    _observation_receipt,
    _open_frozen,
    _plan,
)


@pytest.fixture
def frozen_environment(tmp_path: Path, monkeypatch):
    identity = _identity(tmp_path)
    plan = _plan(tmp_path)
    for name, value in (
        ("FAILED_DRILL_LEDGER_SHA256", plan.failed_ledger_sha256),
        ("FAILED_DRILL_RECEIPT_SHA256", plan.failed_receipt_sha256),
        ("FAILED_DRILL_ROBOTS_SHA256", plan.failed_robots_sha256),
        ("FAILED_DRILL_CONTENT_SHA256", plan.failed_content_sha256),
    ):
        monkeypatch.setattr(recorder_module, name, value)
    monkeypatch.setattr(
        recorder_module,
        "_capture_actual_identity",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        recorder_module,
        "verify_external_time_response",
        _fake_verifier,
    )
    return identity, plan


def test_out_of_order_anchor_and_duplicate_observation_fail_closed(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    with pytest.raises(CohortStateError, match="A2 requires A1"):
        recorder.admit_a2(EMPLOYERS[0], b"a2:x", b"entropy", b"target")
    obs1 = _bind_policy(_observation_receipt(EMPLOYERS[0], 1), identity)
    recorder.admit_obs1_receipt(EMPLOYERS[0], obs1)
    with pytest.raises(CohortStateError, match="manifest order"):
        recorder.admit_obs1_receipt(EMPLOYERS[0], obs1)


def test_a2_below_conservative_24_hours_is_rejected_even_if_a3_would_be_later(
    tmp_path: Path,
    frozen_environment,
    monkeypatch,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])

    def short_verifier(response_bytes, target_receipt_bytes, caller_entropy, prior_anchor=None):
        if response_bytes.startswith(b"a1:"):
            return _fake_verifier(response_bytes, target_receipt_bytes, caller_entropy, prior_anchor)
        return external_time._attestation(
            status=ExternalTimeStatus.VERIFIED,
            reason="cloudflare_roughtime_response_verified",
            receipt_sha256=_digest(target_receipt_bytes),
            entropy_sha256=_digest(caller_entropy),
            nonce_sha256=_digest(b"nonce" + target_receipt_bytes),
            request_sha256=_digest(b"request" + target_receipt_bytes),
            response_sha256=_digest(response_bytes),
            midpoint=1_086_400,
            radius=1,
        )

    monkeypatch.setattr(recorder_module, "verify_external_time_response", short_verifier)
    target = recorder.a2_target_bytes(EMPLOYERS[0])
    with pytest.raises(CohortStateError, match="full conservative 24-hour"):
        recorder.admit_a2(EMPLOYERS[0], b"a2:short", b"entropy", target)
    assert recorder.close_readiness().ready is False


def test_obs2_requires_the_exact_fresh_a2_token(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    target = recorder.a2_target_bytes(EMPLOYERS[0])
    recorder.admit_a2(EMPLOYERS[0], b"a2:x", b"entropy-a2", target)
    attacked = _bind_policy(
        _observation_receipt(EMPLOYERS[0], 2, anchor="f" * 64),
        identity,
    )
    with pytest.raises(CohortStateError, match="surface or anchor"):
        recorder.admit_obs2_receipt(EMPLOYERS[0], attacked)


def test_obs2_cannot_switch_to_another_official_surface(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    target = recorder.a2_target_bytes(EMPLOYERS[0])
    recorder.admit_a2(EMPLOYERS[0], b"a2:x", b"entropy-a2", target)
    token = recorder.a2_token_sha256(EMPLOYERS[0])
    attacked = _bind_policy(
        _observation_receipt(EMPLOYERS[1], 2, anchor=token),
        identity,
    )
    with pytest.raises(CohortStateError, match="surface or anchor"):
        recorder.admit_obs2_receipt(EMPLOYERS[0], attacked)


def test_cross_unit_a2_target_is_rejected(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    _admit_obs1_a1(recorder, identity, EMPLOYERS[1])
    other_target = recorder.a2_target_bytes(EMPLOYERS[1])
    with pytest.raises(CohortStateError, match="cohort/unit/role bound"):
        recorder.admit_a2(EMPLOYERS[0], b"a2:x", b"entropy", other_target)


def test_a2_target_is_bound_to_the_cohort_identity(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, plan = frozen_environment
    first = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(first, identity, EMPLOYERS[0])
    second_path = tmp_path / "second.sqlite3"
    second = recorder_module.ThreeAnchorCohortRecorder.open(
        second_path,
        cohort_id="cohort-b",
        frozen_identity=identity,
    )
    second.freeze_cohort(plan)
    _admit_obs1_a1(second, identity, EMPLOYERS[0])
    assert first.a2_target_bytes(EMPLOYERS[0]) != second.a2_target_bytes(EMPLOYERS[0])


def test_a3_rollback_before_a2_is_rejected(
    tmp_path: Path,
    frozen_environment,
    monkeypatch,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    target = recorder.a2_target_bytes(EMPLOYERS[0])
    recorder.admit_a2(EMPLOYERS[0], b"a2:x", b"entropy-a2", target)
    token = recorder.a2_token_sha256(EMPLOYERS[0])
    obs2 = _bind_policy(_observation_receipt(EMPLOYERS[0], 2, anchor=token), identity)
    recorder.admit_obs2_receipt(EMPLOYERS[0], obs2)

    def rollback_verifier(response_bytes, target_receipt_bytes, caller_entropy, prior_anchor=None):
        if not response_bytes.startswith(b"a3:"):
            return _fake_verifier(
                response_bytes,
                target_receipt_bytes,
                caller_entropy,
                prior_anchor,
            )
        return external_time._attestation(
            status=ExternalTimeStatus.VERIFIED,
            reason="cloudflare_roughtime_response_verified",
            receipt_sha256=_digest(target_receipt_bytes),
            entropy_sha256=_digest(caller_entropy),
            nonce_sha256=_digest(b"nonce" + target_receipt_bytes),
            request_sha256=_digest(b"request" + target_receipt_bytes),
            response_sha256=_digest(response_bytes),
            midpoint=1_086_390,
            radius=1,
        )

    monkeypatch.setattr(recorder_module, "verify_external_time_response", rollback_verifier)
    with pytest.raises(CohortStateError, match="rolls back"):
        recorder.admit_a3(EMPLOYERS[0], b"a3:rollback", b"entropy-a3", obs2)


def test_identity_drift_blocks_every_transition(
    tmp_path: Path,
    frozen_environment,
    monkeypatch,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    monkeypatch.setattr(
        recorder_module,
        "_capture_actual_identity",
        lambda expected: replace(expected, policy_sha256="0" * 64),
    )
    with pytest.raises(FrozenIdentityDriftError):
        recorder.replay()


def test_identity_change_between_before_and_after_capture_fails_closed(
    tmp_path: Path,
    frozen_environment,
    monkeypatch,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    captures = iter((identity, replace(identity, source_tree="0" * 40)))
    monkeypatch.setattr(
        recorder_module,
        "_capture_actual_identity",
        lambda expected: next(captures),
    )
    with pytest.raises(FrozenIdentityDriftError):
        recorder.replay()


def test_journal_chain_rewrite_is_detected(
    tmp_path: Path,
    frozen_environment,
) -> None:
    recorder = _open_frozen(tmp_path, frozen_environment)
    connection = sqlite3.connect(recorder._journal_path)
    connection.execute("DROP TRIGGER cohort_event_no_update")
    connection.execute(
        "UPDATE cohort_event SET previous_receipt_sha256 = ? WHERE sequence = 2",
        ("f" * 64,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(CohortJournalIntegrityError):
        recorder.verify()


def test_missing_and_wrong_mode_artifacts_are_permanent_fail_closed(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    victim = next(path for path in recorder._artifact_dir.iterdir() if path.name.startswith("obs1-"))
    victim.chmod(0o644)
    with pytest.raises(CohortJournalIntegrityError, match="type or mode"):
        recorder.verify()
    victim.chmod(0o444)
    victim.unlink()
    with pytest.raises(CohortJournalIntegrityError, match="absent"):
        recorder.verify()


def test_orphan_and_symlink_artifacts_fail_closed(
    tmp_path: Path,
    frozen_environment,
) -> None:
    recorder = _open_frozen(tmp_path, frozen_environment)
    orphan = recorder._artifact_dir / "orphan.bin"
    orphan.write_bytes(b"orphan")
    orphan.chmod(0o444)
    with pytest.raises(CohortJournalIntegrityError, match="orphan"):
        recorder.verify()
    orphan.unlink()
    target = next(recorder._artifact_dir.iterdir())
    raw = target.read_bytes()
    target.unlink()
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(raw)
    replacement.chmod(0o444)
    target.symlink_to(replacement)
    with pytest.raises(CohortJournalIntegrityError, match="type or mode"):
        recorder.verify()


def test_reused_live_ledger_must_keep_the_two_failed_reservations(
    tmp_path: Path,
    frozen_environment,
) -> None:
    _, plan = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    ledger = Path(plan.reused_live_ledger_path)
    original = ledger.read_bytes()
    ledger.write_bytes(original + _canonical({"sequence": 3}))
    ledger.chmod(0o600)
    recorder.verify()
    ledger.write_bytes(_canonical({"sequence": 2}))
    ledger.chmod(0o600)
    with pytest.raises(CohortJournalIntegrityError, match="lost failed-drill prefix"):
        recorder.verify()


def test_failed_drill_hashes_are_exact_authority_constants(
    tmp_path: Path,
    frozen_environment,
) -> None:
    _, plan = frozen_environment
    recorder = recorder_module.ThreeAnchorCohortRecorder.open(
        tmp_path / "other.sqlite3",
        cohort_id="cohort-b",
        frozen_identity=frozen_environment[0],
    )
    attacked = replace(plan, failed_content_sha256="0" * 64)
    with pytest.raises(CohortStateError, match="identity differs from authority"):
        recorder.freeze_cohort(attacked)


def test_replay_pair_must_be_byte_identical_and_current(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    for unit_id in EMPLOYERS[:10]:
        _admit_obs1_a1(recorder, identity, unit_id)
    for unit_id in EMPLOYERS[:10]:
        _complete_unit(recorder, identity, unit_id)
    first = recorder.replay().to_bytes()
    document = json.loads(first)
    document["event_count"] += 1
    attacked = _canonical(document)
    with pytest.raises(CohortStateError, match="not byte-identical"):
        recorder.admit_replay_pair(first, attacked)


def test_readiness_cannot_shrink_denominators_or_promote_live_claims(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    _complete_unit(recorder, identity, EMPLOYERS[0])
    report = recorder.close_readiness()
    assert report.ready is False
    assert report.document["required_observation_units"] == 10
    assert report.document["minimum_fully_verified_units"] == 8
    assert report.document["minimum_distinct_employers_or_boards"] == 3
    assert report.document["authenticated_separation_seconds"] == 86_400
    assert report.document["certifies_slice"] is False
    assert report.document["submission_authority"] is False
    assert report.document["authenticated_external_time"] is False


def test_module_has_no_acquisition_browser_or_network_capability() -> None:
    source = Path(recorder_module.__file__).read_text()
    lowered = source.casefold()
    for forbidden in (
        "acquire_external_time_attestation",
        "import socket",
        "import requests",
        "import urllib",
        "scrapling",
        "playwright",
        "browser_executor",
        "roughtime.cloudflare.com",
    ):
        assert forbidden not in lowered
    assert "verify_external_time_response" in source
    assert "MINIMUM_AUTHENTICATED_SEPARATION_SECONDS = 86_400" in source
    assert "authenticated_external_time\": False" in source
    assert recorder_module.FAILED_DRILL_LEDGER_SHA256 == (
        "e9994ae7fb081840c8e37ae8f81cc7c57c76109d0471bab771149b271ebcf761"
    )
    assert recorder_module.FAILED_DRILL_RECEIPT_SHA256 == (
        "535bee6625a19041624d25db23dd633e6032d2721bfbdd69bde07ff868063fc6"
    )
