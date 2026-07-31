"""Fail-closed controls for the JAA-11 ranked-snapshot fixture dry run."""

from __future__ import annotations

import ast
import inspect
from dataclasses import replace

import pytest

import career_automation.live_canary_fixture_dry_run as dry_run_module
from career_automation.live_canary_authority import _content_hash
from career_automation.live_canary_fixture_dry_run import (
    compile_live_canary_fixture_dry_run,
)
from test_jaa11_live_canary_fixture_dry_run import (
    _dry_run,
    _evidence,
    _snapshot,
)


def _entries(snapshot: dict[str, object]) -> list[dict[str, object]]:
    entries = snapshot["entries"]
    assert isinstance(entries, list)
    return entries


@pytest.mark.parametrize("count", (0, 1, 20))
def test_underfilled_snapshot_fails_closed(count: int) -> None:
    with pytest.raises(ValueError, match="at least 21"):
        _dry_run(_snapshot(count))


@pytest.mark.parametrize("bad_rank", (0, -1, 2, True, 1.0, "1"))
def test_noncontiguous_or_noninteger_entry_rank_fails_closed(
    bad_rank: object,
) -> None:
    snapshot = _snapshot()
    _entries(snapshot)[0]["rank"] = bad_rank
    with pytest.raises(ValueError, match="contiguous integers"):
        _dry_run(snapshot)


def test_reordered_entries_fail_instead_of_silently_rehashing() -> None:
    snapshot = _snapshot()
    entries = _entries(snapshot)
    entries[0], entries[1] = entries[1], entries[0]
    with pytest.raises(ValueError, match="contiguous integers"):
        _dry_run(snapshot)


@pytest.mark.parametrize(
    ("target", "field"),
    (
        ("snapshot", "ranked_snapshot_sha256"),
        ("snapshot", "unknown"),
        ("entry", "selected_entry_sha256"),
        ("entry", "eligibility_gate_passed"),
        ("evidence", "contract_sha256"),
        ("evidence", "operational_release"),
    ),
)
def test_unknown_or_caller_asserted_fields_are_rejected(
    target: str,
    field: str,
) -> None:
    snapshot = _snapshot()
    evidence = _evidence()
    if target == "snapshot":
        snapshot[field] = "0" * 64
    elif target == "entry":
        _entries(snapshot)[0][field] = "0" * 64
    else:
        evidence[field] = "0" * 64
    with pytest.raises(ValueError, match="missing or unknown"):
        _dry_run(snapshot, evidence)


def test_missing_fields_and_non_objects_fail_closed() -> None:
    snapshot = _snapshot()
    del snapshot["ranking_version"]
    with pytest.raises(ValueError, match="missing or unknown"):
        _dry_run(snapshot)
    snapshot = _snapshot()
    _entries(snapshot)[0] = []  # type: ignore[list-item]
    with pytest.raises(ValueError, match="strict object"):
        _dry_run(snapshot)
    snapshot = _snapshot()
    del _entries(snapshot)[0]["vacancy_identity"]
    with pytest.raises(ValueError, match="missing or unknown"):
        _dry_run(snapshot)
    evidence = _evidence()
    del evidence["selected_rank"]
    with pytest.raises(ValueError, match="missing or unknown"):
        _dry_run(evidence=evidence)


def test_invalid_schema_and_nonlist_entries_fail_closed() -> None:
    snapshot = _snapshot()
    snapshot["schema_version"] = "jaa11.unknown"
    with pytest.raises(ValueError, match="schema is invalid"):
        _dry_run(snapshot)
    snapshot = _snapshot()
    snapshot["entries"] = tuple(_entries(snapshot))
    with pytest.raises(ValueError, match="ordered list"):
        _dry_run(snapshot)


@pytest.mark.parametrize("field", ("vacancy_identity", "vacancy_url"))
def test_duplicate_identity_or_url_fails_closed(field: str) -> None:
    snapshot = _snapshot()
    entries = _entries(snapshot)
    entries[1][field] = entries[0][field]
    with pytest.raises(ValueError, match="must be unique"):
        _dry_run(snapshot)


@pytest.mark.parametrize(
    "url",
    (
        "http://jobs.example.test/vacancies/1",
        "https://user@jobs.example.test/vacancies/1",
        "https://jobs.example.test/vacancies/1#fragment",
        "https:///vacancies/1",
        " https://jobs.example.test/vacancies/1",
    ),
)
def test_unofficial_or_ambiguous_url_fails_closed(url: str) -> None:
    snapshot = _snapshot()
    _entries(snapshot)[0]["vacancy_url"] = url
    with pytest.raises(ValueError, match="official HTTPS URL|whitespace"):
        _dry_run(snapshot)


@pytest.mark.parametrize("digest", ("A" * 64, "0" * 63, "x" * 64))
def test_invalid_content_hash_fails_closed(digest: str) -> None:
    snapshot = _snapshot()
    _entries(snapshot)[0]["vacancy_content_sha256"] = digest
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        _dry_run(snapshot)


@pytest.mark.parametrize(
    ("field", "timestamp"),
    (
        ("snapshot_taken_at", "2026-07-31T12:00:00"),
        ("snapshot_taken_at", "2026-07-31T11:00:00Z"),
        ("vacancy_retrieved_at", "2026-07-31T11:00:00"),
        ("vacancy_retrieved_at", "2026-07-31T10:00:00Z"),
    ),
)
def test_noncanonical_or_naive_timestamps_fail_closed(
    field: str,
    timestamp: str,
) -> None:
    snapshot = _snapshot()
    if field == "snapshot_taken_at":
        snapshot[field] = timestamp
    else:
        _entries(snapshot)[0][field] = timestamp
    with pytest.raises(ValueError, match="canonical aware ISO"):
        _dry_run(snapshot)


def test_retrieval_after_snapshot_fails_closed() -> None:
    snapshot = _snapshot()
    _entries(snapshot)[0]["vacancy_retrieved_at"] = (
        "2026-07-31T12:00:01+01:00"
    )
    with pytest.raises(ValueError, match="cannot postdate"):
        _dry_run(snapshot)


@pytest.mark.parametrize(
    "rank",
    (None, 0, -1, 1, 20, 26, True, 21.0, "21"),
)
def test_invalid_selected_rank_fails_closed(rank: object) -> None:
    evidence = _evidence()
    evidence["selected_rank"] = rank
    with pytest.raises(ValueError, match="outside ranks 1-20"):
        _dry_run(evidence=evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("duplicate_application_found", True),
        ("eligibility_gate_passed", False),
        ("truth_gate_passed", False),
        ("vacancy_open", False),
        ("official_route", False),
        ("selected_only_for_submission_ease", True),
        ("account_creation_required", True),
        ("login_required", True),
        ("mfa_required", True),
        ("captcha_required", True),
        ("payment_required", True),
        ("missing_approved_fact", True),
        ("optional_marketing_consent", "accepted"),
        ("public_acquisition_used", True),
    ),
)
def test_every_selected_entry_gate_fails_closed(
    field: str,
    value: object,
) -> None:
    evidence = _evidence()
    evidence[field] = value
    with pytest.raises(ValueError):
        _dry_run(evidence=evidence)


@pytest.mark.parametrize(
    "field",
    (
        "duplicate_application_found",
        "eligibility_gate_passed",
        "truth_gate_passed",
        "vacancy_open",
        "official_route",
        "selected_only_for_submission_ease",
        "account_creation_required",
        "login_required",
        "mfa_required",
        "captcha_required",
        "payment_required",
        "missing_approved_fact",
        "public_acquisition_used",
    ),
)
@pytest.mark.parametrize("value", (None, 1, "true"))
def test_ambiguous_gate_values_fail_closed(
    field: str,
    value: object,
) -> None:
    evidence = _evidence()
    evidence[field] = value
    with pytest.raises(ValueError, match="unambiguous booleans"):
        _dry_run(evidence=evidence)


@pytest.mark.parametrize(
    ("submission_count", "certified"),
    (
        (1, False),
        (2, False),
        (0, True),
        (None, False),
        (-1, False),
        (False, False),
        (0.5, False),
        ("0", False),
        (0, None),
        (0, "false"),
    ),
)
def test_unavailable_or_ambiguous_authority_fails_closed(
    submission_count: object,
    certified: object,
) -> None:
    with pytest.raises(ValueError, match="unavailable or ambiguous"):
        compile_live_canary_fixture_dry_run(
            _snapshot(),
            _evidence(),
            submission_count=submission_count,  # type: ignore[arg-type]
            jaa11_certified=certified,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("snapshot_is_live", True),
        ("snapshot_is_current", True),
        ("operational_release", "granted"),
        ("may_submit", True),
        ("external_action_capability", True),
        ("certifies_slice", True),
        ("receipt_written", True),
        ("real_applications", 1),
    ),
)
def test_result_cannot_open_any_external_boundary(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="cannot open"):
        replace(_dry_run(), **{field: value})


def test_mutated_documents_no_longer_match_derived_hashes() -> None:
    result = _dry_run()
    snapshot_document = result.snapshot.document()
    snapshot_document["ranking_version"] = "tampered"
    assert _content_hash(snapshot_document) != result.ranked_snapshot_sha256
    assert result.snapshot.snapshot_sha256 == result.ranked_snapshot_sha256
    document = result.document()
    document["operational_release"] = "granted"
    assert _content_hash(document) != result.dry_run_sha256


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("ranked_snapshot_sha256", "0" * 64, "snapshot hash"),
        ("selected_entry_sha256", "0" * 64, "selected-entry hash"),
        ("dry_run_sha256", "0" * 64, "dry-run hash"),
    ),
)
def test_replacing_any_derived_hash_fails_closed(
    field: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(_dry_run(), **{field: value})


def test_module_has_no_io_clock_or_external_capability_imports() -> None:
    source = inspect.getsource(dry_run_module)
    tree = ast.parse(source)
    forbidden = {
        "io",
        "os",
        "pathlib",
        "random",
        "requests",
        "socket",
        "sqlite3",
        "subprocess",
        "time",
    }
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(
                alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
    assert not imports.intersection(forbidden)
    assert "datetime.now" not in source
