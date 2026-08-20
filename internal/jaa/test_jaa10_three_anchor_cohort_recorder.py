"""Positive controls for the pure JAA-10 three-anchor cohort recorder."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
import pytest

from career_automation import external_time_attestation as external_time
from career_automation import three_anchor_cohort_recorder as recorder_module
from career_automation.external_time_attestation import ExternalTimeStatus
from career_automation.observation_route_manifest import (
    LEVER_LIST_ROUTE_CLASS,
    REPLACEMENT_RULE,
    ROUTE_MANIFEST_SCHEMA,
)
from career_automation.public_access import policy_records_hash
from career_automation.three_anchor_cohort_recorder import (
    CohortPlan,
    FrozenIdentity,
    ThreeAnchorCohortRecorder,
    schema_identity_sha256,
)


EMPLOYERS = (
    "jobgether",
    "palantir",
    "spotify",
    "octoenergy",
    "electric-twin",
    "firstup",
    "moneyboxapp",
    "starcompliance",
    "kitmanlabs",
    "binance",
    "gearset",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode() + b"\n"


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, raw: bytes, mode: int) -> str:
    path.write_bytes(raw)
    path.chmod(mode)
    return _digest(raw)


def _manifest(tmp_path: Path) -> tuple[Path, str]:
    document = {
        "schema": ROUTE_MANIFEST_SCHEMA,
        "route_class": LEVER_LIST_ROUTE_CLASS,
        "required_observation_units": 10,
        "minimum_fully_verified_units": 8,
        "minimum_distinct_employers_or_boards": 3,
        "maximum_candidate_attempts": len(EMPLOYERS),
        "replacement_rule": REPLACEMENT_RULE,
        "candidates": [
            {
                "employer_or_board_id": employer,
                "url": (
                    f"https://api.lever.co/v0/postings/{employer}"
                    "?limit=1&mode=json&skip=0"
                ),
            }
            for employer in EMPLOYERS
        ],
    }
    path = tmp_path / "routes.json"
    return path, _write(path, _canonical(document), 0o444)


def _policy(tmp_path: Path) -> tuple[Path, str, str]:
    records = [
        {
            "host": "api.lever.co",
            "terms_url": "https://www.lever.co/legal/terms-of-service",
            "determination": "public_read_only_research_permitted",
            "reviewed_at": "2026-08-02T13:40:00+09:00",
            "reviewed_by": "Test Operator",
            "reviewer_type": "human_operator",
            "notes": "bounded fixture",
        }
    ]
    records_hash = policy_records_hash(records)
    raw = _canonical(
        {
            "schema_version": "jaa04.public-access-policy.v1",
            "hosts": records,
            "records_hash": records_hash,
        }
    )
    path = tmp_path / "policy.json"
    return path, _write(path, raw, 0o600), records_hash


def _identity(tmp_path: Path) -> FrozenIdentity:
    route_path, route_hash = _manifest(tmp_path)
    policy_path, policy_hash, records_hash = _policy(tmp_path)
    return FrozenIdentity(
        repository_root=str(tmp_path),
        source_git_revision="1" * 40,
        source_tree="2" * 40,
        source_content_revision="sha256:" + "3" * 64,
        acquirer_sha256="4" * 64,
        external_time_sha256="5" * 64,
        manifest_module_sha256="6" * 64,
        route_manifest_path=str(route_path.resolve()),
        route_manifest_sha256=route_hash,
        policy_path=str(policy_path.resolve()),
        policy_sha256=policy_hash,
        policy_records_sha256=records_hash,
        recorder_sha256="7" * 64,
        schema_identity_sha256=schema_identity_sha256(),
    )


def _plan(tmp_path: Path) -> CohortPlan:
    ledger = tmp_path / "reservations.jsonl"
    ledger_raw = _canonical({"sequence": 1}) + _canonical({"sequence": 2})
    ledger_hash = _write(ledger, ledger_raw, 0o600)
    receipt = tmp_path / "failed-receipt.json"
    robots = tmp_path / "raw-robots.bin"
    content = tmp_path / "raw-content.bin"
    receipt_hash = _write(receipt, _canonical({"failed": True}), 0o444)
    robots_hash = _write(robots, b"User-agent: *\nAllow: /\n", 0o444)
    content_hash = _write(content, b"[]", 0o444)
    return CohortPlan(
        failed_ledger_path=str(ledger.resolve()),
        failed_ledger_sha256=ledger_hash,
        failed_receipt_path=str(receipt.resolve()),
        failed_receipt_sha256=receipt_hash,
        failed_robots_path=str(robots.resolve()),
        failed_robots_sha256=robots_hash,
        failed_content_path=str(content.resolve()),
        failed_content_sha256=content_hash,
        reused_live_ledger_path=str(ledger.resolve()),
    )


def _url(unit_id: str) -> str:
    return (
        f"https://api.lever.co/v0/postings/{unit_id}"
        "?limit=1&mode=json&skip=0"
    )


def _observation_receipt(
    unit_id: str,
    phase: int,
    *,
    anchor: str | None = None,
) -> bytes:
    url = _url(unit_id)
    robots_event = _digest(f"{unit_id}:{phase}:robots".encode())
    content_event = _digest(f"{unit_id}:{phase}:content".encode())
    body = _canonical([{"id": f"{unit_id}-{phase}", "text": "Engineer"}])
    return _canonical(
        {
            "schema": "jaa10.external-observation-acquisition.v1",
            "acquired_at": f"2026-08-{phase + 1:02d}T00:00:00+00:00",
            "route_class": LEVER_LIST_ROUTE_CLASS,
            "allowed_hosts": ["api.lever.co"],
            "request": {
                "url": url,
                "method": "GET",
                "purpose": "list",
                "effective_kwargs": {},
            },
            "policy_sha256": "POLICY_HASH_REPLACED",
            "terms_attestation": {"host": "api.lever.co"},
            "robots_binding": {"allowed": True},
            "reservation_binding": {
                "schema": "jaa10.external-request-reservation.v1",
                "robots": {"event_sha256": robots_event},
                "content": {
                    "event_sha256": content_event,
                    "prev_event_sha256": robots_event,
                },
                "chain_head_sha256": content_event,
            },
            "pre_observation_anchor_sha256": anchor,
            "response": {
                "status": 200,
                "url": url,
                "body_bytes": len(body),
                "body_sha256": _digest(body),
                "represented_headers_sha256": "8" * 64,
                "represented_request_headers_sha256": "9" * 64,
            },
            "certifies_slice": False,
            "submission_authority": False,
            "authenticated_external_time": False,
            "certifies_raw_header_order": False,
            "certifies_duplicate_header_preservation": False,
            "certifies_wire_transfer_cap": False,
            "body_size_enforced_post_transfer": True,
            "redirects_followed": False,
            "transport_impersonation": False,
            "stealth_headers": False,
            "proxy_used": False,
        }
    )


def _bind_policy(raw: bytes, identity: FrozenIdentity) -> bytes:
    document = json.loads(raw)
    document["policy_sha256"] = identity.policy_sha256
    return _canonical(document)


def _fake_verifier(
    response_bytes: bytes,
    target_receipt_bytes: bytes,
    caller_entropy: bytes,
    prior_anchor=None,
):
    role = response_bytes.decode().split(":", 1)[0]
    midpoints = {"a1": 1_000_000, "a2": 1_086_402, "a3": 1_086_412}
    midpoint = midpoints[role]
    return external_time._attestation(
        status=ExternalTimeStatus.VERIFIED,
        reason="cloudflare_roughtime_response_verified",
        receipt_sha256=_digest(target_receipt_bytes),
        entropy_sha256=_digest(caller_entropy),
        nonce_sha256=_digest(b"nonce:" + target_receipt_bytes + caller_entropy),
        request_sha256=_digest(b"request:" + target_receipt_bytes + caller_entropy),
        response_sha256=_digest(response_bytes),
        midpoint=midpoint,
        radius=1,
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


def _open_frozen(
    tmp_path: Path,
    frozen_environment,
) -> ThreeAnchorCohortRecorder:
    identity, plan = frozen_environment
    recorder = ThreeAnchorCohortRecorder.open(
        tmp_path / "cohort.sqlite3",
        cohort_id="cohort-a",
        frozen_identity=identity,
    )
    freeze = recorder.freeze_cohort(plan)
    assert freeze.document["payload"]["failed_history_non_cohort"] is True
    assert freeze.document["payload"]["failed_history_reservations_counted"] == 2
    assert freeze.document["payload"]["maximum_later_issuer_calls"] == 30
    assert freeze.document["payload"]["p2_issuer_calls"] == 0
    return recorder


def _admit_obs1_a1(
    recorder: ThreeAnchorCohortRecorder,
    identity: FrozenIdentity,
    unit_id: str,
) -> bytes:
    obs1 = _bind_policy(_observation_receipt(unit_id, 1), identity)
    recorder.admit_obs1_receipt(unit_id, obs1)
    recorder.admit_a1(unit_id, f"a1:{unit_id}".encode(), b"entropy-a1:" + unit_id.encode(), obs1)
    return obs1


def _complete_unit(
    recorder: ThreeAnchorCohortRecorder,
    identity: FrozenIdentity,
    unit_id: str,
) -> None:
    target = recorder.a2_target_bytes(unit_id)
    recorder.admit_a2(unit_id, f"a2:{unit_id}".encode(), b"entropy-a2:" + unit_id.encode(), target)
    token = recorder.a2_token_sha256(unit_id)
    obs2 = _bind_policy(_observation_receipt(unit_id, 2, anchor=token), identity)
    recorder.admit_obs2_receipt(unit_id, obs2)
    recorder.admit_a3(unit_id, f"a3:{unit_id}".encode(), b"entropy-a3:" + unit_id.encode(), obs2)


def test_full_cohort_is_durable_replayable_and_ready(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    recorder = ThreeAnchorCohortRecorder.resume(
        recorder._journal_path,
        frozen_identity=identity,
    )
    for unit_id in EMPLOYERS[:10]:
        _admit_obs1_a1(recorder, identity, unit_id)
    recorder = ThreeAnchorCohortRecorder.resume(
        recorder._journal_path,
        frozen_identity=identity,
    )
    for unit_id in EMPLOYERS[:10]:
        _complete_unit(recorder, identity, unit_id)

    first = recorder.replay()
    second = recorder.replay()
    assert first.to_bytes() == second.to_bytes()
    recorder.admit_replay_pair(first.to_bytes(), second.to_bytes())
    report = recorder.close_readiness()

    assert report.ready is True
    assert report.document["complete_units"] == 10
    assert report.document["fully_verified_units"] == 10
    assert report.document["distinct_employers_or_boards"] == 10
    assert report.document["authenticated_separation_seconds"] == 86_400
    assert report.document["maximum_later_issuer_calls"] == 30
    assert report.document["p2_issuer_calls"] == 0
    assert report.document["admitted_anchor_count"] == 30
    assert report.document["restart_drills"] == 2
    assert report.document["restart_spanning_window"] is True
    assert report.document["replay_invocations"] == 2
    assert report.document["certifies_slice"] is False
    assert report.document["submission_authority"] is False
    assert report.document["authenticated_external_time"] is False
    assert report.document["live_execution"] == "not_proven_by_p2"

    restarted = ThreeAnchorCohortRecorder.resume(
        recorder._journal_path,
        frozen_identity=identity,
    )
    assert restarted.close_readiness().ready is True


def test_ordered_miss_advances_only_to_the_next_manifest_candidate(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    recorder.record_candidate_miss(
        EMPLOYERS[0],
        _canonical({"accepted": False, "url": _url(EMPLOYERS[0]), "reason": "empty"}),
    )
    obs1 = _bind_policy(_observation_receipt(EMPLOYERS[1], 1), identity)
    receipt = recorder.admit_obs1_receipt(EMPLOYERS[1], obs1)
    assert receipt.document["payload"]["unit_id"] == EMPLOYERS[1]
    assert recorder.close_readiness().ready is False
    assert "complete_denominator_below_10" in recorder.close_readiness().document[
        "not_ready_reasons"
    ]


def test_published_artifacts_are_content_bound_and_mode_0444(
    tmp_path: Path,
    frozen_environment,
) -> None:
    identity, _ = frozen_environment
    recorder = _open_frozen(tmp_path, frozen_environment)
    obs1 = _admit_obs1_a1(recorder, identity, EMPLOYERS[0])
    assert obs1
    recorder.verify()
    artifacts = list(recorder._artifact_dir.iterdir())
    assert artifacts
    assert all(
        path.is_file()
        and not path.is_symlink()
        and stat.S_IMODE(path.stat().st_mode) == 0o444
        for path in artifacts
    )
