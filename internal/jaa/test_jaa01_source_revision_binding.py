"""Black-box source-revision binding checks for JAA-01 runtime receipts.

The digest below is intentionally implemented here, rather than imported from
the certifier. It is the verifier's view of the documented receipt contract:
the current Git index names the inputs and the checked-out bytes supply their
content. Mutation cases use the admitted serial in-place fixture.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

import test_jaa04_increment_a_certifier_fail_closed as inplace_fixture

ROOT = Path(__file__).resolve().parent
DOMAIN = b"jaa-source-content-revision-v2\0"
EXCLUDED_PREFIXES = (b"runtime_evidence/",)
MIGRATION_CONTENT_HASH = (
    "b38b38fc4455ce6142ca156a4eff400c5dba22ab04d64f02fce8cd332fe08971"
)


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ("git", *args),
        cwd=root,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def _head(root: Path) -> str:
    return _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()


def _independent_source_revision(root: Path) -> str:
    """Calculate the published revision without importing certifier code."""
    entries: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    for record in _git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        mode, _object_id, stage = metadata.split()
        assert separator and stage == b"0" and path not in seen
        seen.add(path)
        if not path.startswith(EXCLUDED_PREFIXES):
            entries.append((path, mode))

    digest = hashlib.sha256(DOMAIN)
    for path, declared_mode in sorted(entries):
        candidate = root / os.fsdecode(path)
        status = candidate.lstat()
        if declared_mode == b"120000":
            assert stat.S_ISLNK(status.st_mode)
            payload = os.fsencode(os.readlink(candidate))
        else:
            assert declared_mode in {b"100644", b"100755"}
            assert stat.S_ISREG(status.st_mode)
            payload = candidate.read_bytes()
        for field in (path, declared_mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return f"sha256:{digest.hexdigest()}"


def _runtime() -> Path:
    for parent in ROOT.parents:
        runtime = parent / "state" / "runtime"
        matches = (
            sorted(
                runtime.glob(
                    f"jaa00-v2-*/receipts/migration-{MIGRATION_CONTENT_HASH}.json"
                )
            )
            if runtime.is_dir()
            else []
        )
        if len(matches) == 1:
            return matches[0].parents[1]
    pytest.fail("frozen JAA-00 runtime is unavailable")


def _request_params(request: pytest.FixtureRequest) -> dict[str, object]:
    callspec = getattr(request.node, "callspec", None)
    return {} if callspec is None else callspec.params


def _mutation_relative_path(request: pytest.FixtureRequest) -> str | None:
    name = request.node.originalname
    params = _request_params(request)
    if name in {
        "test_every_source_class_byte_changes_the_independent_revision",
        "test_every_remaining_tracked_source_class_changes_the_independent_revision",
        "test_generated_receipt_bytes_do_not_change_source_revision",
    }:
        return str(params["relative"])
    if name in {
        "test_certifier_rejects_unsafe_tracked_source_trees",
        "test_certifier_fails_closed_for_tracked_mode_and_type_drift",
    }:
        return "README.md"
    if name == "test_certifier_rejects_dirty_tracked_jaa00_trust_evidence":
        return "runtime_evidence/JAA-00-online-snapshot.yaml"
    if name == "test_tampered_and_stale_source_revision_fields_are_rejected_by_independent_verifier":
        return "docs/UK_SOURCE_RESEARCH.md"
    return None


def _snapshot_test_path(
    relative: str | None,
    *,
    validate_index_binding: bool = True,
) -> dict[str, object] | None:
    if relative is None:
        return None
    repository_path = f"internal/jaa/{relative}"
    target = inplace_fixture._safe_mutation_target(repository_path)
    try:
        target_stat = target.lstat()
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None and stat.S_ISLNK(target_stat.st_mode):
        kind = "symlink"
        content: bytes | None = os.fsencode(os.readlink(target))
        mode: int | None = None
    elif target_stat is not None and stat.S_ISREG(target_stat.st_mode):
        kind = "file"
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            content = stream.read()
        mode = stat.S_IMODE(target_stat.st_mode)
    elif target_stat is not None:
        raise RuntimeError("in-place source-revision target is not a regular file")
    else:
        kind = "absent"
        content = None
        mode = None
    entries = _index_entries(relative)
    encoded_repository_path = os.fsencode(repository_path)
    if any(
        _index_entry_fields(entry)[3] != encoded_repository_path
        for entry in entries
    ):
        raise RuntimeError("source-revision index query returned an unexpected path")
    if kind != "absent" and validate_index_binding:
        if len(entries) != 1:
            raise RuntimeError("source-revision target does not have exactly one index entry")
        index_mode, object_id, stage, index_path = _index_entry_fields(entries[0])
        expected_mode = (
            b"120000"
            if kind == "symlink"
            else b"100755" if int(mode) & 0o111 else b"100644"
        )
        if (
            index_path != encoded_repository_path
            or stage != b"0"
            or index_mode != expected_mode
            or object_id != _git(ROOT, "hash-object", "--stdin", input=content).strip()
        ):
            raise RuntimeError("source-revision target bytes, mode, or index entry disagree")
    parents: list[str] = []
    parent = target.parent
    while parent != ROOT:
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            parents.append(parent.relative_to(ROOT).as_posix())
        else:
            if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
                raise RuntimeError("source-revision output parent is not a real directory")
        parent = parent.parent
    return {
        "relative": relative,
        "repository_path": repository_path,
        "kind": kind,
        "content": content,
        "mode": mode,
        "index_entries": entries,
        "absent_parents": tuple(parents),
    }


def _index_entry_fields(entry: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    metadata, separator, path = entry.partition(b"\t")
    fields = metadata.split()
    if not separator or len(fields) != 3:
        inplace_fixture._abort_suite("source-revision index entry is malformed")
    return fields[0], fields[1], fields[2], path


def _index_entries(relative: str) -> tuple[bytes, ...]:
    return tuple(
        entry
        for entry in _git(
            ROOT,
            "ls-files",
            "--stage",
            "--full-name",
            "-z",
            "--",
            relative,
        ).split(b"\0")
        if entry
    )


def _status_lines() -> list[str]:
    return _git(ROOT, "status", "--porcelain", "--untracked-files=all").decode().splitlines()


def _assert_only_status_path(repository_path: str) -> None:
    lines = _status_lines()
    if len(lines) != 1 or lines[0][3:] != repository_path:
        inplace_fixture._abort_suite("source-revision test changed more than its exact path")


def _assert_regular_state(target: Path, expected_bytes: bytes, expected_mode: int) -> None:
    try:
        current_stat = target.lstat()
    except FileNotFoundError:
        inplace_fixture._abort_suite("source-revision mutation target disappeared unexpectedly")
    if (
        not stat.S_ISREG(current_stat.st_mode)
        or stat.S_ISLNK(current_stat.st_mode)
        or stat.S_IMODE(current_stat.st_mode) != expected_mode
    ):
        inplace_fixture._abort_suite("source-revision mutation target type or mode is unexpected")
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        if stream.read() != expected_bytes:
            inplace_fixture._abort_suite("source-revision mutation bytes are unexpected")


def _assert_snapshot_restored(snapshot: dict[str, object]) -> None:
    current = _snapshot_test_path(str(snapshot["relative"]))
    if current != snapshot or _status_lines():
        inplace_fixture._abort_suite("source-revision path did not return to its exact original state")


def _restore_generated_receipt(
    state: inplace_fixture._FixtureBranch,
    snapshot: dict[str, object],
) -> None:
    relative = str(snapshot["relative"])
    repository_path = str(snapshot["repository_path"])
    target = ROOT / relative
    if snapshot["kind"] != "absent" or snapshot["index_entries"]:
        _assert_snapshot_restored(snapshot)
        return
    if not target.exists() and not target.is_symlink() and not _index_entries(relative):
        _assert_snapshot_restored(snapshot)
        return

    generated = b'{"generated":"changed"}\n'
    expected_entry = (
        b"100644 "
        + _git(ROOT, "hash-object", "--stdin", input=generated).strip()
        + b" 0\t"
        + os.fsencode(repository_path)
    )
    if _index_entries(relative) != (expected_entry,):
        inplace_fixture._abort_suite("generated receipt staged blob, mode, or path is not exact")
    _assert_regular_state(target, generated, 0o644)
    if _status_lines() != [f"A  {repository_path}"]:
        inplace_fixture._abort_suite("generated receipt stage status is not exact")

    inplace_fixture._assert_admission(state.branch, state.head, True)
    _git(ROOT, "update-index", "--force-remove", "--", relative)
    if _index_entries(relative):
        inplace_fixture._abort_suite("generated receipt index entry remained after removal")
    status_after_unstage = _status_lines()
    if status_after_unstage not in ([], [f"?? {repository_path}"]):
        inplace_fixture._abort_suite("generated receipt unstaged status is unexpected")
    inplace_fixture._assert_admission(state.branch, state.head, bool(status_after_unstage))
    _assert_regular_state(target, generated, 0o644)
    if _index_entries(relative):
        inplace_fixture._abort_suite("generated receipt index changed before file removal")

    inplace_fixture._assert_admission(state.branch, state.head, bool(status_after_unstage))
    target.unlink()
    if target.exists() or target.is_symlink() or _index_entries(relative) or _status_lines():
        inplace_fixture._abort_suite("generated receipt cleanup left bytes, index state, or status")
    for relative_parent in snapshot["absent_parents"]:
        parent = ROOT / str(relative_parent)
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or stat.S_ISLNK(parent_stat.st_mode)
            or any(parent.iterdir())
        ):
            inplace_fixture._abort_suite("generated receipt parent contains unexpected data")
        inplace_fixture._assert_admission(state.branch, state.head, False)
        parent.rmdir()
    _assert_snapshot_restored(snapshot)
    inplace_fixture._assert_admission(state.branch, state.head, False)


def _restore_unmerged_index(
    target: Path,
    snapshot: dict[str, object],
    state: inplace_fixture._FixtureBranch,
) -> None:
    relative = str(snapshot["relative"])
    repository_path = os.fsencode(str(snapshot["repository_path"]))
    original_entries = snapshot["index_entries"]
    if (
        snapshot["kind"] != "file"
        or snapshot["content"] is None
        or snapshot["mode"] is None
        or len(original_entries) != 1
    ):
        inplace_fixture._abort_suite("unmerged-index snapshot is not one original tracked file")
    original_entry = original_entries[0]
    original_mode, original_oid, original_stage, original_path = _index_entry_fields(original_entry)
    if original_stage != b"0" or original_path != repository_path or original_mode != b"100644":
        inplace_fixture._abort_suite("unmerged-index original entry is not the exact stage-0 source")

    _assert_regular_state(target, snapshot["content"], int(snapshot["mode"]))
    staged = _index_entries(relative)
    parsed = sorted((_index_entry_fields(entry) for entry in staged), key=lambda item: item[2])
    if (
        len(parsed) != 2
        or [entry[2] for entry in parsed] != [b"1", b"2"]
        or any(
            mode != b"100644" or object_id != original_oid or path != repository_path
            for mode, object_id, _stage, path in parsed
        )
    ):
        inplace_fixture._abort_suite("unmerged index stages differ from the exact expected mode, blob, or path")
    _assert_only_status_path(str(snapshot["repository_path"]))
    if not _status_lines()[0].startswith("UD "):
        inplace_fixture._abort_suite("unmerged index status differs from the observed stage-1/stage-2 conflict")

    inplace_fixture._assert_admission(state.branch, state.head, True)
    clear_entry = (
        b"0 "
        + b"0" * len(original_oid)
        + b"\t"
        + repository_path
        + b"\0"
    )
    _git(
        inplace_fixture.REPOSITORY_ROOT,
        "update-index",
        "-z",
        "--index-info",
        input=clear_entry + original_entry + b"\0",
    )
    if _index_entries(relative) != (original_entry,) or _status_lines():
        inplace_fixture._abort_suite("saved original NUL index record did not restore the exact clean entry")
    _assert_regular_state(target, snapshot["content"], int(snapshot["mode"]))
    inplace_fixture._assert_admission(state.branch, state.head, False)


def _restore_test_mutation(
    request: pytest.FixtureRequest,
    state: inplace_fixture._FixtureBranch,
    snapshot: dict[str, object] | None,
) -> None:
    if snapshot is None:
        if _status_lines():
            inplace_fixture._abort_suite("source-revision test changed an unapproved project path")
        return
    name = request.node.originalname
    params = _request_params(request)
    if name == "test_generated_receipt_bytes_do_not_change_source_revision":
        _restore_generated_receipt(state, snapshot)
        return

    status = _status_lines()
    if state.commit_records:
        if (
            name != "test_certifier_rejects_unsafe_tracked_source_trees"
            or params.get("attack") != "symlink_escape"
            or len(state.commit_records) != 1
            or state.commit_records[0].operation != "symlink"
            or state.commit_records[0].path != str(snapshot["repository_path"])
            or status
        ):
            inplace_fixture._abort_suite("source-revision fixture has an unexpected committed mutation")
        target = ROOT / str(snapshot["relative"])
        expected_link = b"/private/jaa01-source-revision-escape"
        entries = _index_entries(str(snapshot["relative"]))
        if (
            not target.is_symlink()
            or os.fsencode(os.readlink(target)) != expected_link
            or len(entries) != 1
            or _index_entry_fields(entries[0])
            != (
                b"120000",
                _git(ROOT, "hash-object", "--stdin", input=expected_link).strip(),
                b"0",
                os.fsencode(str(snapshot["repository_path"])),
            )
        ):
            inplace_fixture._abort_suite("committed symlink does not match its exact source mutation")
        return

    if not status and _snapshot_test_path(
        str(snapshot["relative"]), validate_index_binding=False
    ) == snapshot:
        return
    repository_path = str(snapshot["repository_path"])
    _assert_only_status_path(repository_path)
    inplace_fixture._assert_admission(state.branch, state.head, True)
    relative = str(snapshot["relative"])
    target = ROOT / relative
    kind = str(snapshot["kind"])
    original = snapshot["content"]
    original_mode = snapshot["mode"]
    original_entries = snapshot["index_entries"]

    if name in {
        "test_every_source_class_byte_changes_the_independent_revision",
        "test_every_remaining_tracked_source_class_changes_the_independent_revision",
    }:
        suffix = (
            b"\nsource-revision-adversarial-byte\n"
            if name == "test_every_source_class_byte_changes_the_independent_revision"
            else b"\nindependent-revision-class-probe\n"
        )
        if kind != "file" or original is None or original_mode is None:
            inplace_fixture._abort_suite("source-revision byte case has no original regular file")
        _assert_regular_state(target, original + suffix, int(original_mode))
        if _index_entries(relative) != original_entries:
            inplace_fixture._abort_suite("source-revision byte mutation changed its staged entry")
        _write_original_file(target, original, int(original_mode), already_exists=True, state=state)
    elif name == "test_certifier_rejects_unsafe_tracked_source_trees":
        attack = params["attack"]
        if attack == "dirty":
            _assert_regular_state(target, original + b"\ndirty\n", int(original_mode))
            if _index_entries(relative) != original_entries:
                inplace_fixture._abort_suite("dirty-source attack changed its staged entry")
            _write_original_file(target, original, int(original_mode), already_exists=True, state=state)
        elif attack == "missing":
            if target.exists() or target.is_symlink() or _index_entries(relative) != original_entries:
                inplace_fixture._abort_suite("missing-source attack differs from its exact test input")
            _write_original_file(target, original, int(original_mode), already_exists=False, state=state)
        elif attack == "unmerged":
            _restore_unmerged_index(target, snapshot, state)
        elif attack == "symlink_escape":
            inplace_fixture._abort_suite("committed symlink case lost its fixture commit record")
        else:
            inplace_fixture._abort_suite("source-revision unsafe-tree case is unknown")
    elif name == "test_certifier_fails_closed_for_tracked_mode_and_type_drift":
        attack = params["attack"]
        if attack == "mode":
            expected_mode = int(original_mode) | stat.S_IXUSR
            _assert_regular_state(target, original, expected_mode)
            if _index_entries(relative) != original_entries:
                inplace_fixture._abort_suite("mode-drift attack changed its staged entry")
            inplace_fixture._assert_admission(state.branch, state.head, True)
            target.chmod(int(original_mode))
        elif attack == "type":
            if not target.is_symlink() or os.readlink(target) != "SOURCE_BASELINE.md":
                inplace_fixture._abort_suite("type-drift attack differs from its exact test input")
            if _index_entries(relative) != original_entries:
                inplace_fixture._abort_suite("type-drift attack changed its staged entry")
            inplace_fixture._assert_admission(state.branch, state.head, True)
            target.unlink()
            _write_original_file(target, original, int(original_mode), already_exists=False, state=state)
        else:
            inplace_fixture._abort_suite("source-revision mode/type case is unknown")
    elif name == "test_certifier_rejects_dirty_tracked_jaa00_trust_evidence":
        _assert_regular_state(target, original + b"\n# untrusted mutation\n", int(original_mode))
        if _index_entries(relative) != original_entries:
            inplace_fixture._abort_suite("dirty trust-evidence mutation changed its staged entry")
        _write_original_file(target, original, int(original_mode), already_exists=True, state=state)
    elif name == "test_tampered_and_stale_source_revision_fields_are_rejected_by_independent_verifier":
        _assert_regular_state(target, b"stale receipt source byte\n", int(original_mode))
        if _index_entries(relative) != original_entries:
            inplace_fixture._abort_suite("stale-source mutation changed its staged entry")
        _write_original_file(target, original, int(original_mode), already_exists=True, state=state)
    else:
        inplace_fixture._abort_suite("source-revision fixture cleanup has no exact restoration rule")

    _assert_snapshot_restored(snapshot)
    inplace_fixture._assert_admission(state.branch, state.head, False)


def _write_original_file(
    target: Path,
    content: bytes,
    mode: int,
    *,
    already_exists: bool,
    state: inplace_fixture._FixtureBranch,
) -> None:
    inplace_fixture._assert_admission(state.branch, state.head, True)
    flags = os.O_WRONLY | os.O_NOFOLLOW
    if already_exists:
        if not target.is_file() or target.is_symlink():
            inplace_fixture._abort_suite("restore target is not the expected regular file")
        flags |= os.O_TRUNC
    else:
        if target.exists() or target.is_symlink():
            inplace_fixture._abort_suite("restore target unexpectedly exists")
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(target, flags, mode)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        inplace_fixture._abort_suite("exact source-revision restoration failed; preserving current state")


@pytest.fixture()
def source_revision_state(request: pytest.FixtureRequest) -> Iterator[inplace_fixture._FixtureBranch]:
    params = _request_params(request)
    symlink_commit = (
        request.node.originalname == "test_certifier_rejects_unsafe_tracked_source_trees"
        and params.get("attack") == "symlink_escape"
    )
    mutation_path = _mutation_relative_path(request)
    case = re.sub(r"[^a-z0-9-]+", "-", request.node.name.lower()).strip("-")[:36]
    allowed = {"internal/jaa/README.md"} if symlink_commit else set()
    with inplace_fixture._committed_inplace_branch(
        f"jaa01-source-{case}", allowed_mutations=allowed
    ) as state:
        snapshot: dict[str, object] | None = None
        try:
            snapshot = _snapshot_test_path(mutation_path)
            if (
                request.node.originalname == "test_generated_receipt_bytes_do_not_change_source_revision"
                and snapshot is not None
                and (snapshot["kind"] != "absent" or snapshot["index_entries"])
            ):
                inplace_fixture._abort_suite(
                    "generated receipt file or index entry already exists; preserving it"
                )
            yield state
        finally:
            if snapshot is not None:
                _restore_test_mutation(request, state, snapshot)


@pytest.fixture()
def isolated_repository(source_revision_state: inplace_fixture._FixtureBranch) -> Path:
    return ROOT


def _create_generated_receipt(
    target: Path,
    relative: str,
    state: inplace_fixture._FixtureBranch,
) -> None:
    missing_parents: list[Path] = []
    parent = target.parent
    while parent != ROOT:
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            missing_parents.append(parent)
        else:
            if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
                inplace_fixture._abort_suite("generated receipt parent is not a real directory")
        parent = parent.parent
    for parent in reversed(missing_parents):
        if parent.exists() or parent.is_symlink():
            inplace_fixture._abort_suite("generated receipt parent appeared after its locked snapshot")
        inplace_fixture._assert_admission(state.branch, state.head, False)
        parent.mkdir(mode=0o755)
    if target.exists() or target.is_symlink():
        inplace_fixture._abort_suite("generated receipt target appeared after its locked snapshot")
    inplace_fixture._assert_admission(state.branch, state.head, False)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(b'{"generated":"changed"}\n')
        stream.flush()
        os.fsync(stream.fileno())
    inplace_fixture._assert_admission(state.branch, state.head, bool(_status_lines()))
    _git(ROOT, "add", "-f", "--", relative)
    repository_path = f"internal/jaa/{relative}"
    oid = _git(ROOT, "hash-object", "--stdin", input=b'{"generated":"changed"}\n').strip()
    expected_entry = b"100644 " + oid + b" 0\t" + os.fsencode(repository_path)
    if (
        _index_entries(relative) != (expected_entry,)
        or _status_lines() != [f"A  {repository_path}"]
    ):
        inplace_fixture._abort_suite("generated receipt did not stage as the exact regular-file blob")


def _certify(
    root: Path, evidence_name: str = "evidence"
) -> tuple[Path, dict[str, object]]:
    runtime = _runtime()
    database = runtime / "databases" / "career_pipeline.sqlite3"
    receipt = runtime / "receipts" / f"migration-{MIGRATION_CONTENT_HASH}.json"
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/certify_jaa01_runtime.py",
            "--baseline-database",
            str(database),
            "--migration-receipt",
            str(receipt),
            "--expected-source-commit",
            _head(root),
            "--evidence-directory",
            evidence_name,
        ),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = root / Path(json.loads(completed.stdout)["receipt"])
    return output, json.loads(output.read_text(encoding="utf-8"))


def _assert_source_binding(
    root: Path, receipt: Path, document: dict[str, object]
) -> None:
    rendered = receipt.read_text(encoding="utf-8")
    assert (
        receipt.name
        == f"sha256-{hashlib.sha256(receipt.read_bytes()).hexdigest()}.json"
    )
    assert document["source_content_revision"] == _independent_source_revision(root)
    assert document["source_content_revision_contract"] == {
        "algorithm": "sha256",
        "domain": "jaa-source-content-revision-v2",
        "entry_encoding": "uint64be-length-prefixed-path-mode-content",
        "scope": "current-tracked-source-tree",
        "ordering": "repository-relative-path-byte-order",
        "exclusions": ["runtime_evidence/"],
    }
    assert document["source_git_revision"] == _head(root)
    assert document["source_git_revision_contract"] == {
        "algorithm": "git-commit-sha1",
        "reference": "HEAD^{commit}",
        "scope": "exact-source-commit",
    }
    assert str(root) not in rendered
    assert not any(value.startswith("/") for value in _strings(document))


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []


def test_fresh_receipt_matches_independent_current_tree_revision(
    isolated_repository: Path,
) -> None:
    receipt, document = _certify(isolated_repository)
    _assert_source_binding(isolated_repository, receipt, document)


def test_certifier_rejects_a_clean_but_unexpected_git_revision(
    tmp_path: Path,
) -> None:
    database = tmp_path / "absent-baseline.sqlite3"
    receipt = tmp_path / "absent-migration-receipt.json"
    evidence = tmp_path / "unexpected-revision-evidence"

    completed = subprocess.run(
        (
            sys.executable,
            "scripts/certify_jaa01_runtime.py",
            "--baseline-database",
            str(database),
            "--migration-receipt",
            str(receipt),
            "--expected-source-commit",
            "0" * 40,
            "--evidence-directory",
            str(evidence),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "does not match the expected component revision" in completed.stderr
    assert not list(evidence.glob("*.json"))


def test_certifier_rejects_dirty_tracked_jaa00_trust_evidence(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
) -> None:
    trust_evidence = (
        isolated_repository / "runtime_evidence" / "JAA-00-online-snapshot.yaml"
    )
    inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
    trust_evidence.write_bytes(
        trust_evidence.read_bytes() + b"\n# untrusted mutation\n"
    )
    runtime = _runtime()
    database = runtime / "databases" / "career_pipeline.sqlite3"
    receipt = runtime / "receipts" / f"migration-{MIGRATION_CONTENT_HASH}.json"

    completed = subprocess.run(
        (
            sys.executable,
            "scripts/certify_jaa01_runtime.py",
            "--baseline-database",
            str(database),
            "--migration-receipt",
            str(receipt),
            "--expected-source-commit",
            _head(isolated_repository),
            "--evidence-directory",
            "evidence",
        ),
        cwd=isolated_repository,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert (
        "JAA-00 certification evidence must be tracked and unchanged"
        in completed.stderr
    )
    assert not list((isolated_repository / "evidence").glob("*.json"))


@pytest.mark.parametrize(
    "relative",
    [
        "career_automation/lifecycle.py",
        "career_automation/migrations.py",
        "test_jaa01_adversarial_runtime.py",
        "SOURCE_BASELINE.md",
        "README.md",
    ],
)
def test_every_source_class_byte_changes_the_independent_revision(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
    relative: str,
) -> None:
    before = _independent_source_revision(isolated_repository)
    target = isolated_repository / relative
    inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
    target.write_bytes(target.read_bytes() + b"\nsource-revision-adversarial-byte\n")
    assert _independent_source_revision(isolated_repository) != before


@pytest.mark.parametrize(
    "relative",
    [
        "canonical-repository.json",
        "skeleton/config.yaml",
        "llm/schemas/job_extract.json",
        "scraper/fixtures/jobkorea_listing.json",
        "scripts/advance_career_pipeline.py",
        "requirements-test.lock",
        "acceptance",
    ],
)
def test_every_remaining_tracked_source_class_changes_the_independent_revision(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
    relative: str,
) -> None:
    """Configuration, fixtures, locks, and executable sources are digest inputs too."""
    before = _independent_source_revision(isolated_repository)
    target = isolated_repository / relative
    inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
    target.write_bytes(target.read_bytes() + b"\nindependent-revision-class-probe\n")
    assert _independent_source_revision(isolated_repository) != before


@pytest.mark.parametrize(
    "relative",
    [
        "runtime_evidence/jaa01/manual-receipt.json",
        "runtime_evidence/pytest/manual-receipt.json",
        "runtime_evidence/jaa02/manual-receipt.json",
        "runtime_evidence/future/nested/output.bin",
    ],
)
def test_generated_receipt_bytes_do_not_change_source_revision(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
    relative: str,
) -> None:
    before = _independent_source_revision(isolated_repository)
    target = isolated_repository / relative
    _create_generated_receipt(target, relative, source_revision_state)
    assert _independent_source_revision(isolated_repository) == before


@pytest.mark.parametrize(
    "attack, expected",
    [
        ("dirty", "dirty tracked source tree"),
        # Git reports a deleted tracked file as dirty before the certifier opens it.
        ("missing", "dirty tracked source tree"),
        ("unmerged", "unmerged tracked source path"),
        ("symlink_escape", "tracked symlink escapes or has a missing target"),
    ],
)
def test_certifier_rejects_unsafe_tracked_source_trees(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
    attack: str,
    expected: str,
) -> None:
    target = isolated_repository / "README.md"
    if attack == "dirty":
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
        target.write_bytes(target.read_bytes() + b"\ndirty\n")
    elif attack == "missing":
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
        target.unlink()
    elif attack == "unmerged":
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
        blob = _git(isolated_repository, "hash-object", "-w", "README.md").strip()
        repository_prefix = _git(
            isolated_repository, "rev-parse", "--show-prefix"
        ).strip()
        index_path = repository_prefix + b"README.md"
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
        _git(
            isolated_repository,
            "update-index",
            "-z",
            "--index-info",
            input=(
                b"100644 "
                + blob
                + b" 1\t"
                + index_path
                + b"\0"
                + b"100644 "
                + blob
                + b" 2\t"
                + index_path
                + b"\0"
            ),
        )
    else:
        inplace_fixture._commit_symlink_change(
            source_revision_state,
            "internal/jaa/README.md",
            "/private/jaa01-source-revision-escape",
            "source-revision-symlink-escape",
        )

    completed = subprocess.run(
        (
            sys.executable,
            "scripts/certify_jaa01_runtime.py",
            "--baseline-database",
            "absent.sqlite3",
            "--migration-receipt",
            "absent.json",
            "--expected-source-commit",
            _head(isolated_repository),
            "--evidence-directory",
            "evidence",
        ),
        cwd=isolated_repository,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert expected in completed.stderr


@pytest.mark.parametrize("attack", ["mode", "type"])
def test_certifier_fails_closed_for_tracked_mode_and_type_drift(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
    attack: str,
) -> None:
    """A Git index entry must never be trusted when its checkout type changes."""
    target = isolated_repository / "README.md"
    if attack == "mode":
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
        target.chmod(target.stat().st_mode | stat.S_IXUSR)
    else:
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
        target.unlink()
        inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, True)
        target.symlink_to("SOURCE_BASELINE.md")

    completed = subprocess.run(
        (
            sys.executable,
            "scripts/certify_jaa01_runtime.py",
            "--baseline-database",
            "absent.sqlite3",
            "--migration-receipt",
            "absent.json",
            "--expected-source-commit",
            _head(isolated_repository),
            "--evidence-directory",
            "evidence",
        ),
        cwd=isolated_repository,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "dirty tracked source tree" in completed.stderr
    assert not list((isolated_repository / "evidence").glob("*.json"))


def test_tampered_and_stale_source_revision_fields_are_rejected_by_independent_verifier(
    isolated_repository: Path,
    source_revision_state: inplace_fixture._FixtureBranch,
) -> None:
    receipt, document = _certify(isolated_repository)
    _assert_source_binding(isolated_repository, receipt, document)

    tampered = dict(document)
    tampered["source_content_revision"] = "sha256:" + "0" * 64
    with pytest.raises(AssertionError):
        _assert_source_binding(isolated_repository, receipt, tampered)

    inplace_fixture._assert_admission(source_revision_state.branch, source_revision_state.head, False)
    (isolated_repository / "docs" / "UK_SOURCE_RESEARCH.md").write_bytes(
        b"stale receipt source byte\n"
    )
    with pytest.raises(AssertionError):
        _assert_source_binding(isolated_repository, receipt, document)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_source_content_revision_preserves_git_object_format(tmp_path: Path, object_format: str) -> None:
    from tracked_source_revision import source_content_revision, TrackedSourceRevisionError

    _git(tmp_path, "init", f"--object-format={object_format}")
    _git(tmp_path, "config", "user.name", "Synthetic test")
    _git(tmp_path, "config", "user.email", "synthetic@example.invalid")
    (tmp_path / "empty").write_bytes(b"")
    (tmp_path / "binary").write_bytes(bytes(range(256)))
    (tmp_path / "text").write_bytes(b"line one\r\nline two\n")
    (tmp_path / "link").symlink_to("text")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "Synthetic source fixture")
    assert source_content_revision(tmp_path) == _independent_source_revision(tmp_path)
    (tmp_path / "text").write_bytes(b"changed")
    with pytest.raises(TrackedSourceRevisionError, match="dirty tracked source"):
        source_content_revision(tmp_path)


def test_source_git_ignores_ambient_repository_and_global_configuration(tmp_path, monkeypatch):
    import tracked_source_revision as revision
    from test_jaa10_linux_network_namespace_witness_negative_controls import _clean_repository

    source = _clean_repository(tmp_path / "repository")
    expected = revision.source_git_revision(source)
    global_config = tmp_path / "config"
    global_config.write_text("[alias]\nsynthetic-probe = !exit 99\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "nonexistent"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "wrong-tree"))
    assert revision.source_git_revision(source) == expected
    with pytest.raises(revision.TrackedSourceRevisionError):
        revision._git(source, "synthetic-probe")


def test_source_git_timeout_has_domain_error(tmp_path, monkeypatch):
    import tracked_source_revision as revision

    def timed_out(*args, **kwargs):
        assert args[0][0] == str(revision.GIT_EXECUTABLE)
        assert kwargs["timeout"] == 10
        assert kwargs["close_fds"] is True
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(revision.subprocess, "run", timed_out)
    with pytest.raises(revision.TrackedSourceRevisionError, match="timed out"):
        revision._git(tmp_path, "status")
