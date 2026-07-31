"""Adversarial controls for JAA-10 frozen replay-pair recording."""

from __future__ import annotations

import copy
import inspect
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import career_automation.frozen_replay_pair_recorder as recorder
from career_automation.frozen_replay_pair_recorder import (
    REPLAY_OBSERVATION_1_FILENAME,
    REPLAY_OBSERVATION_2_FILENAME,
    REPLAY_PAIR_FILENAME,
    ReplayExecutionEnvironmentError,
    ReplayPairIntegrityError,
    record_frozen_replay_pair,
    stable_projection,
)
from career_automation.shadow_certification import (
    normalized_submit_event_sha256,
)
from test_jaa10_independent_acceptance import _observation


IDENTITY = {
    "source_git_revision": "1" * 40,
    "source_tree": "2" * 40,
    "source_content_revision": f"sha256:{'3' * 64}",
}
EEI_SHA256 = "4" * 64


def _observations():
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    return (
        _observation("replay-negative-1", first_time),
        _observation(
            "replay-negative-2",
            first_time + timedelta(seconds=1),
        ),
    )


@pytest.fixture
def accepted_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recorder,
        "_capture_replay_execution_identity",
        lambda: dict(IDENTITY),
    )
    monkeypatch.setattr(
        recorder,
        "_capture_replay_eei",
        lambda identity: EEI_SHA256,
    )


def test_secondary_documents_and_missing_observation_are_rejected(
    tmp_path: Path,
) -> None:
    first, second = _observations()
    with pytest.raises(TypeError, match="two typed"):
        record_frozen_replay_pair(  # type: ignore[arg-type]
            {"test_passed": True},
            second,
            destination_directory=tmp_path,
        )
    with pytest.raises(TypeError):
        record_frozen_replay_pair(  # type: ignore[call-arg]
            first,
            destination_directory=tmp_path,
        )


def test_duplicate_observation_or_release_identity_is_rejected(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    first, second = _observations()
    with pytest.raises(ReplayPairIntegrityError, match="distinct"):
        record_frozen_replay_pair(
            first,
            first,
            destination_directory=tmp_path,
        )
    object.__setattr__(second, "release_manifest_sha256", first.release_manifest_sha256)
    with pytest.raises(ValueError, match="submission proof differs"):
        record_frozen_replay_pair(
            first,
            second,
            destination_directory=tmp_path,
        )


def test_internally_consistent_golden_workflow_drift_is_rejected(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    first, second = _observations()
    changed_workflow = "a" * 64
    changed = replace(
        second,
        workflow_sha256=changed_workflow,
        normalized_submit_event_sha256=normalized_submit_event_sha256(
            workflow_sha256=changed_workflow,
            receipt_id=second.receipt_id,
            receipt_payload_sha256=second.receipt_payload_sha256,
            screenshot_sha256=second.screenshot_sha256,
            field_map_sha256=second.field_map_sha256,
        ),
    )
    with pytest.raises(ReplayPairIntegrityError, match="workflow_sha256"):
        record_frozen_replay_pair(
            first,
            changed,
            destination_directory=tmp_path,
        )


def test_projection_rejects_unknown_missing_and_wrong_schema_documents() -> None:
    first, _ = _observations()
    document = first.document()
    unknown = {**document, "future_field": "silently skipped"}
    missing = dict(document)
    missing.pop("step_id")
    wrong_schema = {**document, "schema_version": "jaa10.shadow-observation.v3"}
    for candidate in (unknown, missing, wrong_schema):
        with pytest.raises(ReplayPairIntegrityError, match="inventory|schema"):
            recorder._stable_projection_document(candidate)


def test_run_variant_changes_do_not_create_a_false_mismatch() -> None:
    first, _ = _observations()
    changed = replace(
        first,
        observation_id="different-observation-id",
        observed_at="2035-05-05T12:00:00+00:00",
        action_elapsed_ms={
            key: value + 1000 for key, value in first.action_elapsed_ms.items()
        },
        database_bytes=first.database_bytes + 4096,
        screenshot_bytes=first.screenshot_bytes + 1024,
    )
    assert stable_projection(first) == stable_projection(changed)


def test_included_field_drift_is_diagnostic_and_cannot_be_relabelled(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    first, second = _observations()
    changed = replace(second, browser_launch_count=2)
    pair = record_frozen_replay_pair(
        first,
        changed,
        destination_directory=tmp_path,
    )
    assert pair.mismatch_count == 1
    tampered = copy.copy(pair)
    object.__setattr__(tampered, "mismatch_count", 0)
    with pytest.raises(ReplayPairIntegrityError, match="derivation"):
        tampered.verify()


def test_reordered_embedded_observations_break_the_pair_binding(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    first, second = _observations()
    pair = record_frozen_replay_pair(
        first,
        second,
        destination_directory=tmp_path,
    )
    tampered = copy.copy(pair)
    object.__setattr__(tampered, "observation_1", second)
    object.__setattr__(tampered, "observation_2", first)
    with pytest.raises(ReplayPairIntegrityError, match="binding"):
        tampered.verify()


@pytest.mark.parametrize(
    "occupied_name",
    (
        REPLAY_OBSERVATION_1_FILENAME,
        REPLAY_OBSERVATION_2_FILENAME,
        REPLAY_PAIR_FILENAME,
    ),
)
def test_preexisting_destination_refuses_without_partial_publication(
    tmp_path: Path,
    accepted_capture: None,
    occupied_name: str,
) -> None:
    (tmp_path / occupied_name).write_text("occupied", encoding="utf-8")
    first, second = _observations()
    with pytest.raises(ReplayPairIntegrityError, match="all be absent"):
        record_frozen_replay_pair(
            first,
            second,
            destination_directory=tmp_path,
        )
    assert sorted(path.name for path in tmp_path.iterdir()) == [occupied_name]


def test_symlinked_destination_is_rejected(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    first, second = _observations()
    with pytest.raises(ReplayPairIntegrityError, match="symlink"):
        record_frozen_replay_pair(
            first,
            second,
            destination_directory=link,
        )
    assert not any(real.iterdir())


def test_api_exposes_no_caller_verdict_target_source_or_filename() -> None:
    assert tuple(inspect.signature(record_frozen_replay_pair).parameters) == (
        "first",
        "second",
        "destination_directory",
    )
    assert tuple(inspect.signature(stable_projection).parameters) == (
        "observation",
    )
    source = Path(recorder.__file__).read_text(encoding="utf-8")
    for forbidden_import in (
        "import subprocess",
        "import socket",
        "import playwright",
        "import requests",
        "import urllib",
        "from career_automation.browser_",
        "from career_automation.ats_fixture",
    ):
        assert forbidden_import not in source


def _admissible_eei_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path]:
    cache = tmp_path / "cache"
    cache.mkdir()
    browser = tmp_path / "browser"
    browser.mkdir()
    (browser / "chromium").write_bytes(b"pinned-browser")
    for name in recorder._FORBIDDEN_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", str(cache))
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(browser))
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    monkeypatch.setattr(sys, "pycache_prefix", str(cache))
    return cache, browser


def test_eei_binds_browser_bytes_and_rejects_forbidden_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, browser = _admissible_eei_environment(monkeypatch, tmp_path)
    first_hash = recorder._capture_replay_eei(IDENTITY)
    (browser / "chromium").write_bytes(b"changed-browser")
    second_hash = recorder._capture_replay_eei(IDENTITY)
    assert first_hash != second_hash
    monkeypatch.setenv("PYTHONPATH", "/tmp/injected")
    with pytest.raises(
        ReplayExecutionEnvironmentError,
        match="forbidden",
    ):
        recorder._capture_replay_eei(IDENTITY)


def test_eei_rejects_nonfresh_cache_prefix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache, _ = _admissible_eei_environment(monkeypatch, tmp_path)
    (cache / "poison.pyc").write_bytes(b"poison")
    with pytest.raises(
        ReplayExecutionEnvironmentError,
        match="fresh empty",
    ):
        recorder._capture_replay_eei(IDENTITY)


def test_current_integration_checkout_is_not_an_admissible_frozen_source() -> None:
    with pytest.raises(
        ReplayExecutionEnvironmentError,
        match="clean detached",
    ):
        recorder._capture_replay_execution_identity()


def test_capture_failure_publishes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = _observations()

    def reject():
        raise ReplayExecutionEnvironmentError("identity rejected")

    monkeypatch.setattr(recorder, "_capture_replay_execution_identity", reject)
    with pytest.raises(ReplayExecutionEnvironmentError, match="identity"):
        record_frozen_replay_pair(
            first,
            second,
            destination_directory=tmp_path,
        )
    assert not any(tmp_path.iterdir())
