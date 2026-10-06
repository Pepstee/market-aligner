from __future__ import annotations

import hashlib
import json

from market_aligner.profiler.recovery_manifest import select_recovered_input_descriptors


_APPROVAL = "synthetic-approval-01"
_PROFILE = "candidate_profile_and_job_preferences"
_EVIDENCE = "existing_profile_claims_and_provenance"


def _row(kind, path):
    return {
        "kind": kind,
        "destination_relative": path,
        "sha256": "a" * 64 if kind == _PROFILE else "b" * 64,
        "bytes": 17 if kind == _PROFILE else 23,
        "source_path": "/never/open/source",
    }


def _manifest(files=None):
    return {
        "schema": "market-aligner.private-input-recovery.v1",
        "approval_id": _APPROVAL,
        "files": files if files is not None else [
            _row(_PROFILE, "profiles/prf_synthetic/profile-β.yaml"),
            {"kind": "unrelated", "source_path": "/ignored", "extra": True},
            _row(_EVIDENCE, "profiles/prf_synthetic/evidence.jsonl"),
        ],
        "ignored_root_field": {"metadata": "not returned"},
    }


def _encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _select(raw, approval=_APPROVAL):
    return select_recovered_input_descriptors(raw, hashlib.sha256(raw).hexdigest(), approval)


def _refuses(raw, approval=_APPROVAL):
    try:
        _select(raw, approval)
    except ValueError as exc:
        assert str(exc) == "recovered_input_manifest_invalid"
    else:
        raise AssertionError("invalid recovered-input manifest was accepted")


def test_contract():
    original = _manifest()
    raw = _encode(original)
    result = _select(raw)
    assert result == {
        _PROFILE: {
            "relative_path": "profiles/prf_synthetic/profile-β.yaml",
            "sha256": "a" * 64,
            "bytes": 17,
        },
        _EVIDENCE: {
            "relative_path": "profiles/prf_synthetic/evidence.jsonl",
            "sha256": "b" * 64,
            "bytes": 23,
        },
    }
    assert _select(raw) == result
    assert original == _manifest()
    assert "source_path" not in str(result)
    try:
        select_recovered_input_descriptors(raw, "0" * 64, _APPROVAL)
    except ValueError as exc:
        assert str(exc) == "recovered_input_manifest_invalid"
    else:
        raise AssertionError("manifest digest mismatch was accepted")

    changed = _manifest()
    changed["schema"] = "wrong"
    _refuses(_encode(changed))
    _refuses(raw, "wrong-approval")
    _refuses(b"not-json")
    _refuses(b"[]")
    _refuses(b'{"schema":"market-aligner.private-input-recovery.v1","schema":"duplicate"}')
    nonfinite = _manifest()
    nonfinite["ignored_root_field"] = float("nan")
    _refuses(_encode(nonfinite))

    for files in (
        [],
        {},
        [None],
        [_row(_PROFILE, "a"), _row(_PROFILE, "b"), _row(_EVIDENCE, "c")],
    ):
        changed = _manifest()
        changed["files"] = files
        _refuses(_encode(changed))
    for invalid_path in (
        "",
        "/absolute",
        "//double-root",
        "a/",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
        "a:b",
        "a\x00b",
    ):
        changed = _manifest()
        changed["files"][0]["destination_relative"] = invalid_path
        _refuses(_encode(changed))

    invalid_rows = []
    missing = _manifest()
    missing["files"] = [_row(_PROFILE, "a")]
    invalid_rows.append(missing)
    duplicate = _manifest()
    duplicate["files"].append(_row(_EVIDENCE, "another"))
    invalid_rows.append(duplicate)
    same_path = _manifest()
    same_path["files"][2]["destination_relative"] = same_path["files"][0]["destination_relative"]
    invalid_rows.append(same_path)
    bad_digest = _manifest()
    bad_digest["files"][0]["sha256"] = "A" * 64
    invalid_rows.append(bad_digest)
    for size in (0, True):
        bad_size = _manifest()
        bad_size["files"][0]["bytes"] = size
        invalid_rows.append(bad_size)
    for changed in invalid_rows:
        _refuses(_encode(changed))

    class BytesSubclass(bytes):
        pass

    class StringSubclass(str):
        pass

    try:
        select_recovered_input_descriptors(BytesSubclass(raw), hashlib.sha256(raw).hexdigest(), _APPROVAL)
    except ValueError as exc:
        assert str(exc) == "recovered_input_manifest_invalid"
    else:
        raise AssertionError("bytes subclass was accepted")
    try:
        select_recovered_input_descriptors(raw, StringSubclass(hashlib.sha256(raw).hexdigest()), _APPROVAL)
    except ValueError as exc:
        assert str(exc) == "recovered_input_manifest_invalid"
    else:
        raise AssertionError("string subclass was accepted")
