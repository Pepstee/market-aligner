"""Positive controls for JAA-10 frozen localhost replay-pair recording."""

from __future__ import annotations

import json
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import career_automation.frozen_replay_pair_recorder as recorder
from career_automation.frozen_replay_pair_recorder import (
    REPLAY_OBSERVATION_1_FILENAME,
    REPLAY_OBSERVATION_2_FILENAME,
    REPLAY_PAIR_FILENAME,
    STABLE_PROJECTION_VERSION,
    FrozenReplayPair,
    record_frozen_replay_pair,
    stable_projection,
    stable_projection_sha256,
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
        _observation("replay-primary-1", first_time),
        _observation(
            "replay-primary-2",
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


def test_stable_projection_is_exhaustive_and_excludes_run_variants() -> None:
    first, second = _observations()
    projection = stable_projection(first)
    assert tuple(projection) == recorder._STABLE_KEYS
    assert projection["step_id"] == "submit"
    assert projection["fixture_receipt"] == first.fixture_receipt.document()
    for excluded in (
        "observation_id",
        "observed_at",
        "run_id",
        "durable_workflow_sha256",
        "release_manifest_sha256",
        "submit_event_sha256",
        "submission_proof",
        "action_elapsed_ms",
        "database_bytes",
        "screenshot_bytes",
    ):
        assert excluded not in projection
    assert stable_projection(first) == stable_projection(second)
    assert stable_projection_sha256(first) == stable_projection_sha256(second)


def test_pair_publication_is_primary_complete_exclusive_and_withheld(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    first, second = _observations()
    pair = record_frozen_replay_pair(
        first,
        second,
        destination_directory=tmp_path,
    )
    pair.verify()
    assert isinstance(pair, FrozenReplayPair)
    assert pair.mismatch_count == 0
    assert pair.mismatched_stable_fields == ()
    assert pair.replay_execution_identity == IDENTITY
    assert pair.execution_environment_sha256 == EEI_SHA256

    paths = [
        tmp_path / REPLAY_OBSERVATION_1_FILENAME,
        tmp_path / REPLAY_OBSERVATION_2_FILENAME,
        tmp_path / REPLAY_PAIR_FILENAME,
    ]
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in paths)
    documents = [json.loads(path.read_bytes()) for path in paths]
    assert documents[0]["observation"] == first.document()
    assert documents[1]["observation"] == second.document()
    assert documents[2] == pair.document()
    assert documents[2]["stable_projection_version"] == (
        STABLE_PROJECTION_VERSION
    )
    for document in documents:
        assert document["evidence_class"] == "fixture_frozen"
        assert document["objective_satisfied"] is False
        assert document["certifies_slice"] is False
        assert document["live_time_separated_execution"] == "not_collected"
        assert document["production_certification"] == "withheld"
        assert document["external_action_capability"] is False
        assert document["real_applications_submitted"] == 0


def test_one_stable_difference_derives_one_pair_mismatch(
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
    assert pair.mismatched_stable_fields == ("browser_launch_count",)
    assert pair.stable_field_hash_1 != pair.stable_field_hash_2
    pair.verify()


def test_replay_recording_has_no_twenty_four_hour_predicate(
    tmp_path: Path,
    accepted_capture: None,
) -> None:
    first, second = _observations()
    assert (
        datetime.fromisoformat(second.observed_at)
        - datetime.fromisoformat(first.observed_at)
    ) == timedelta(seconds=1)
    pair = record_frozen_replay_pair(
        first,
        second,
        destination_directory=tmp_path,
    )
    assert pair.document()["time_authenticated"] is False


def test_pair_type_cannot_be_constructed_directly() -> None:
    with pytest.raises(TypeError, match="verified recorder"):
        FrozenReplayPair()
