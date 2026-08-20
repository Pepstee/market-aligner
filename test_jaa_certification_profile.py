from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import jaa_certification_profile as profile


REPOSITORY_ROOT = Path(__file__).resolve().parent


def _write_evidence(
    base: Path,
    evidence_id: str,
    files: dict[str, bytes],
) -> profile.EvidenceHook:
    root = base / evidence_id
    root.mkdir()
    entries: list[dict[str, str]] = []
    manifest_lines: list[str] = []
    for relative, payload in sorted(files.items()):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        entries.append({"path": relative, "sha256": digest})
        manifest_lines.append(f"{digest}  {relative}\n")
    manifest = base / f"{evidence_id}.sha256"
    manifest.write_text("".join(manifest_lines), encoding="utf-8")
    return profile.EvidenceHook(
        evidence_id=evidence_id,
        root=root,
        manifest=manifest,
        expected_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        expected_content_sha256=profile._domain_hash(
            profile.EVIDENCE_CONTENT_DOMAIN, entries
        ),
        required_paths=tuple(sorted(files)),
    )


@pytest.fixture()
def hooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[profile.EvidenceHook]:
    corpus_inventory = b'{"schema":"test-corpus"}\n'
    certificate = b'{"result":"OPUS_JAA10_EXACT_SOURCE_CERTIFICATION: CERTIFIED"}\n'
    external = b'{"schema":"jaa10-test-external-control"}\n'
    linux_acceptance = b'{"result":"historical-linux-acceptance"}\n'
    linux_runtime = b'{"result":"historical-linux-runtime"}\n'
    values = [
        _write_evidence(
            tmp_path,
            "jaa09_exact_corpus",
            {"corpus_inventory.json": corpus_inventory},
        ),
        _write_evidence(
            tmp_path,
            "jaa10_external_control",
            {"registry.json": external},
        ),
        _write_evidence(
            tmp_path,
            "jaa10_exact_source_certificate",
            {"opus-jaa10-exact-source-certification-raw.json": certificate},
        ),
        _write_evidence(
            tmp_path,
            "jaa10_linux_historical_evidence",
            {
                "historical-acceptance.json": linux_acceptance,
                "historical-runtime.json": linux_runtime,
            },
        ),
    ]
    monkeypatch.setattr(
        profile,
        "JAA09_CORPUS_INVENTORY_SHA256",
        hashlib.sha256(corpus_inventory).hexdigest(),
    )
    monkeypatch.setattr(
        profile,
        "JAA09_CORPUS_MANIFEST_SHA256",
        values[0].expected_manifest_sha256,
    )
    monkeypatch.setattr(
        profile,
        "JAA10_EXACT_SOURCE_CERTIFICATE_SHA256",
        hashlib.sha256(certificate).hexdigest(),
    )
    monkeypatch.setattr(
        profile,
        "JAA10_LINUX_HISTORICAL_EVIDENCE_SHA256S",
        frozenset(
            {
                hashlib.sha256(linux_acceptance).hexdigest(),
                hashlib.sha256(linux_runtime).hexdigest(),
            }
        ),
    )
    monkeypatch.setattr(
        profile,
        "_source_identity",
        lambda _root: {
            "git_revision": profile.EXACT_SOURCE_GIT_REVISION,
            "tree": profile.EXACT_SOURCE_TREE,
            "worktree_clean_including_untracked": True,
            "certified_base_git_revision": profile.EXACT_SOURCE_GIT_REVISION,
            "certified_base_tree": profile.EXACT_SOURCE_TREE,
            "certified_base_is_ancestor": True,
            "exact_source_certificate_applies_to_current_source": True,
            "post_import_independent_certification_required": False,
        },
    )
    return values


def _mac() -> profile.HostCapabilities:
    return profile.HostCapabilities(
        system="Darwin",
        machine="arm64",
        has_proc=False,
        unshare_sha256=None,
        ip_sha256=None,
        setpriv_sha256=None,
    )


def _linux() -> profile.HostCapabilities:
    return profile.HostCapabilities(
        system="Linux",
        machine="x86_64",
        has_proc=True,
        unshare_sha256=profile.PINNED_LINUX_TOOL_SHA256["/usr/bin/unshare"],
        ip_sha256=profile.PINNED_LINUX_TOOL_SHA256["/usr/sbin/ip"],
        setpriv_sha256=profile.PINNED_LINUX_TOOL_SHA256["/usr/bin/setpriv"],
    )


def test_mac_profile_enumerates_every_observed_platform_exclusion(
    hooks: list[profile.EvidenceHook],
) -> None:
    document = profile.build_profile(REPOSITORY_ROOT, hooks, _mac())
    excluded = [item["test"] for item in document["linux_only_exclusions"]]
    assert excluded == list(profile.MAC_INAPPLICABLE_TESTS)
    assert set(document["applicable_tests"]) == (
        set(profile.KNOWN_TESTS) - set(profile.MAC_INAPPLICABLE_TESTS)
    )
    assert document["profile_kind"] == "mac-with-retained-linux-evidence"


def test_mac_exclusions_distinguish_historical_network_evidence_from_unrun_suites(
    hooks: list[profile.EvidenceHook],
) -> None:
    document = profile.build_profile(REPOSITORY_ROOT, hooks, _mac())
    historical = next(
        item
        for item in document["evidence"]
        if item["evidence_id"] == "jaa10_linux_historical_evidence"
    )
    for exclusion in document["linux_only_exclusions"]:
        if exclusion["test"] in profile.LINUX_NAMESPACE_TESTS:
            assert exclusion["historical_evidence_available"] is True
            assert exclusion["historical_manifest_sha256"] == historical[
                "manifest_sha256"
            ]
            assert exclusion["historical_content_sha256"] == historical[
                "content_sha256"
            ]
            assert exclusion["historical_source_revisions"] == list(
                profile.JAA10_LINUX_HISTORICAL_REVISIONS
            )
        else:
            assert exclusion["historical_evidence_available"] is False
            assert exclusion["historical_evidence_id"] is None
            assert exclusion["historical_manifest_sha256"] is None
            assert exclusion["historical_content_sha256"] is None
            assert exclusion["historical_source_revisions"] == []
        assert exclusion["current_source_linux_execution_verified"] is False
        assert exclusion["current_source_linux_execution_required"] is True
        assert exclusion["certified_by_this_profile"] is False
    assert document["claims"]["current_source_linux_execution_verified"] is False


def test_linux_profile_runs_every_explicit_known_test(
    hooks: list[profile.EvidenceHook],
) -> None:
    document = profile.build_profile(REPOSITORY_ROOT, hooks, _linux())
    assert document["applicable_tests"] == list(profile.KNOWN_TESTS)
    assert document["linux_only_exclusions"] == []
    assert document["profile_kind"] == "linux-full"


def test_linux_with_unpinned_tools_is_rejected(
    hooks: list[profile.EvidenceHook],
) -> None:
    unpinned = profile.HostCapabilities(
        system="Linux",
        machine="x86_64",
        has_proc=True,
        unshare_sha256="0" * 64,
        ip_sha256=profile.PINNED_LINUX_TOOL_SHA256["/usr/sbin/ip"],
        setpriv_sha256=profile.PINNED_LINUX_TOOL_SHA256["/usr/bin/setpriv"],
    )
    with pytest.raises(profile.CertificationProfileError, match="lacks the exact"):
        profile.build_profile(REPOSITORY_ROOT, hooks, unpinned)


def test_profile_and_selection_receipt_never_claim_product_or_jaa11(
    hooks: list[profile.EvidenceHook],
) -> None:
    document = profile.build_profile(REPOSITORY_ROOT, hooks, _mac())
    receipt = profile.selection_receipt(document)
    assert document["scope"] == ["JAA-09", "JAA-10"]
    assert document["claims"]["product_certified"] is False
    assert document["claims"]["jaa11_certified"] is False
    assert document["claims"]["skipped_product_test_certified"] is False
    assert receipt["claims"]["product_certified"] is False
    assert receipt["claims"]["jaa11_certified"] is False
    assert receipt["claims"]["retained_linux_tests_certified_by_this_receipt"] is False


def test_profile_identity_is_canonical_and_deterministic(
    hooks: list[profile.EvidenceHook],
) -> None:
    first = profile.build_profile(REPOSITORY_ROOT, hooks, _mac())
    second = profile.build_profile(REPOSITORY_ROOT, list(reversed(hooks)), _mac())
    assert first == second
    identity = first.pop("profile_sha256")
    assert identity == profile._domain_hash(profile.PROFILE_DOMAIN, first)


def test_missing_or_unknown_evidence_hook_is_rejected(
    hooks: list[profile.EvidenceHook],
) -> None:
    with pytest.raises(profile.CertificationProfileError, match="exact required"):
        profile.build_profile(REPOSITORY_ROOT, hooks[:-1], _mac())
    unknown = profile.EvidenceHook(
        evidence_id="jaa11_forbidden",
        root=hooks[-1].root,
        manifest=hooks[-1].manifest,
        expected_manifest_sha256=hooks[-1].expected_manifest_sha256,
        expected_content_sha256=hooks[-1].expected_content_sha256,
        required_paths=hooks[-1].required_paths,
    )
    with pytest.raises(profile.CertificationProfileError, match="exact required"):
        profile.build_profile(REPOSITORY_ROOT, [*hooks, unknown], _mac())


def test_symlink_evidence_root_is_rejected(
    hooks: list[profile.EvidenceHook], tmp_path: Path
) -> None:
    link = tmp_path / "linked-root"
    link.symlink_to(hooks[1].root, target_is_directory=True)
    bad = profile.EvidenceHook(
        evidence_id=hooks[1].evidence_id,
        root=link,
        manifest=hooks[1].manifest,
        expected_manifest_sha256=hooks[1].expected_manifest_sha256,
        expected_content_sha256=hooks[1].expected_content_sha256,
        required_paths=hooks[1].required_paths,
    )
    with pytest.raises(profile.CertificationProfileError, match="must not be a symlink"):
        profile._validate_evidence_hook(bad)


def test_tool_hash_accepts_stable_executable_symlink(tmp_path: Path) -> None:
    target = tmp_path / "tool-target"
    target.write_bytes(b"pinned-tool")
    target.chmod(0o700)
    link = tmp_path / "tool-link"
    link.symlink_to(target.name)
    assert profile._tool_hash(str(link)) == hashlib.sha256(b"pinned-tool").hexdigest()


def test_tool_hash_rejects_broken_or_nonexecutable_target(tmp_path: Path) -> None:
    broken = tmp_path / "broken"
    broken.symlink_to("missing")
    assert profile._tool_hash(str(broken)) is None
    target = tmp_path / "not-executable"
    target.write_bytes(b"tool")
    assert profile._tool_hash(str(target)) is None


def test_symlink_member_is_rejected(
    hooks: list[profile.EvidenceHook], tmp_path: Path
) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    member = hooks[1].root / "member-link.json"
    member.symlink_to(target)
    with pytest.raises(profile.CertificationProfileError, match="contains a symlink"):
        profile._validate_evidence_hook(hooks[1])


def test_manifest_hash_or_content_hash_mismatch_is_rejected(
    hooks: list[profile.EvidenceHook],
) -> None:
    bad_manifest = profile.EvidenceHook(
        evidence_id=hooks[1].evidence_id,
        root=hooks[1].root,
        manifest=hooks[1].manifest,
        expected_manifest_sha256="0" * 64,
        expected_content_sha256=hooks[1].expected_content_sha256,
        required_paths=hooks[1].required_paths,
    )
    with pytest.raises(profile.CertificationProfileError, match="manifest hash"):
        profile._validate_evidence_hook(bad_manifest)
    bad_content = profile.EvidenceHook(
        evidence_id=hooks[1].evidence_id,
        root=hooks[1].root,
        manifest=hooks[1].manifest,
        expected_manifest_sha256=hooks[1].expected_manifest_sha256,
        expected_content_sha256="0" * 64,
        required_paths=hooks[1].required_paths,
    )
    with pytest.raises(profile.CertificationProfileError, match="content identity"):
        profile._validate_evidence_hook(bad_content)


def test_mutated_or_extra_evidence_is_rejected(
    hooks: list[profile.EvidenceHook],
) -> None:
    member = hooks[1].root / hooks[1].required_paths[0]
    member.write_text("mutated", encoding="utf-8")
    with pytest.raises(profile.CertificationProfileError, match="hash mismatch"):
        profile._validate_evidence_hook(hooks[1])

    member.write_text(
        '{"schema":"jaa10-test-external-control"}\n', encoding="utf-8"
    )
    (hooks[1].root / "unmanifested.json").write_text("{}", encoding="utf-8")
    with pytest.raises(profile.CertificationProfileError, match="inventory differs"):
        profile._validate_evidence_hook(hooks[1])


def test_execution_binding_rejects_unknown_missing_skip_failure_and_error(
    hooks: list[profile.EvidenceHook],
) -> None:
    document = profile.build_profile(REPOSITORY_ROOT, hooks, _mac())
    passed = {test: "passed" for test in document["applicable_tests"]}
    with pytest.raises(profile.CertificationProfileError, match="not exact"):
        profile.bind_execution_results(document, {**passed, "unknown.py": "passed"})
    missing = dict(passed)
    missing.pop(next(iter(missing)))
    with pytest.raises(profile.CertificationProfileError, match="not exact"):
        profile.bind_execution_results(document, missing)
    for status in ("skipped", "failed", "error", "unclassified"):
        bad = dict(passed)
        bad[next(iter(bad))] = status
        with pytest.raises(profile.CertificationProfileError, match="forbidden"):
            profile.bind_execution_results(document, bad)


def test_all_pass_execution_receipt_remains_non_product_certificate(
    hooks: list[profile.EvidenceHook],
) -> None:
    document = profile.build_profile(REPOSITORY_ROOT, hooks, _mac())
    outcomes = {test: "passed" for test in document["applicable_tests"]}
    receipt = profile.bind_execution_results(document, outcomes)
    assert receipt["claims"]["all_applicable_profile_tests_passed"] is True
    assert receipt["claims"]["product_certified"] is False
    assert receipt["claims"]["jaa11_certified"] is False
    assert receipt["claims"]["excluded_linux_tests_certified_by_this_receipt"] is False


def test_unknown_or_missing_test_file_is_rejected(tmp_path: Path) -> None:
    for name in profile.KNOWN_TESTS:
        (tmp_path / name).write_text("", encoding="utf-8")
    profile._validate_repository_tests(tmp_path)
    (tmp_path / "test_jaa10_secret_unknown.py").write_text("", encoding="utf-8")
    with pytest.raises(profile.CertificationProfileError, match="unknown JAA tests"):
        profile._validate_repository_tests(tmp_path)
    (tmp_path / "test_jaa10_secret_unknown.py").unlink()
    (tmp_path / profile.KNOWN_TESTS[0]).unlink()
    with pytest.raises(profile.CertificationProfileError, match="known JAA tests are missing"):
        profile._validate_repository_tests(tmp_path)


def test_actual_imported_jaa09_manifest_and_inventory_are_exact() -> None:
    configured = os.environ.get("JAA_CERTIFICATION_EVIDENCE_CONFIG")
    if configured:
        hook = next(
            item
            for item in profile.load_evidence_config(Path(configured))
            if item.evidence_id == "jaa09_exact_corpus"
        )
        manifest = hook.manifest
        root = hook.root
        manifest_prefix = hook.manifest_path_prefix
    else:
        evidence = Path(
            "/Users/admin/Projects/"
            "job-application-automation-gutua-20260803-evidence/external-control"
        )
        manifest = evidence / (
            "sha256-f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
            ".files.sha256"
        )
        root = evidence / (
            "sha256-f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
        )
        manifest_prefix = (
            "/Users/admin/Projects/"
            "job-application-automation-gutua-20260803-evidence/external-control/"
            "jaa09-corpus-f93733a"
        )
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == (
        profile.JAA09_CORPUS_MANIFEST_SHA256
    )
    entries = profile._parse_sha256_manifest(
        manifest.read_bytes(),
        absolute_prefix=manifest_prefix,
    )
    assert entries["corpus_inventory.json"] == profile.JAA09_CORPUS_INVENTORY_SHA256
    assert hashlib.sha256((root / "corpus_inventory.json").read_bytes()).hexdigest() == (
        profile.JAA09_CORPUS_INVENTORY_SHA256
    )


def test_evidence_config_is_exact_and_round_trips(
    hooks: list[profile.EvidenceHook], tmp_path: Path
) -> None:
    document = {
        "schema_version": profile.EVIDENCE_CONFIG_SCHEMA,
        "hooks": [
            {
                "evidence_id": hook.evidence_id,
                "root": str(hook.root),
                "manifest": str(hook.manifest),
                "expected_manifest_sha256": hook.expected_manifest_sha256,
                "expected_content_sha256": hook.expected_content_sha256,
                "required_paths": list(hook.required_paths),
                "manifest_path_prefix": hook.manifest_path_prefix,
            }
            for hook in hooks
        ],
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert profile.load_evidence_config(path) == hooks


def test_source_identity_distinguishes_certified_base_from_clean_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current_revision = "a" * 40
    current_tree = "b" * 40

    def fake_git(_root: Path, *args: str) -> str:
        if args[:2] == ("status", "--porcelain=v1"):
            assert args[-1] == "--untracked-files=all"
            return ""
        if args == ("rev-parse", "HEAD"):
            return current_revision
        if args == ("rev-parse", "HEAD^{tree}"):
            return current_tree
        raise AssertionError(args)

    monkeypatch.setattr(profile, "_git", fake_git)
    monkeypatch.setattr(
        profile.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )
    identity = profile._source_identity(tmp_path)
    assert identity["git_revision"] == current_revision
    assert identity["certified_base_is_ancestor"] is True
    assert identity["exact_source_certificate_applies_to_current_source"] is False
    assert identity["post_import_independent_certification_required"] is True


def test_source_identity_rejects_untracked_or_unrelated_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        profile,
        "_git",
        lambda _root, *args: "?? new_source.py" if args[0] == "status" else "",
    )
    with pytest.raises(profile.CertificationProfileError, match="untracked"):
        profile._source_identity(tmp_path)

    def clean_git(_root: Path, *args: str) -> str:
        if args[0] == "status":
            return ""
        if args == ("rev-parse", "HEAD"):
            return "a" * 40
        if args == ("rev-parse", "HEAD^{tree}"):
            return "b" * 40
        raise AssertionError(args)

    monkeypatch.setattr(profile, "_git", clean_git)
    monkeypatch.setattr(
        profile.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    with pytest.raises(profile.CertificationProfileError, match="not a descendant"):
        profile._source_identity(tmp_path)
