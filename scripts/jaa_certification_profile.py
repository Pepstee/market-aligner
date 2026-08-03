#!/usr/bin/env python3
"""Build an explicit JAA-09/JAA-10 host certification profile.

This module defines *which* tests are applicable on a host and validates the
immutable evidence inputs needed by those tests.  It deliberately does not
run pytest and it never certifies JAA-11 or the product.  Execution results can
be bound later with :func:`bind_execution_results`; any missing, skipped,
failed, errored, or unknown applicable test is rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


PROFILE_SCHEMA = "jaa.certification-profile.v1"
SELECTION_RECEIPT_SCHEMA = "jaa.certification-profile-selection-receipt.v1"
EXECUTION_RECEIPT_SCHEMA = "jaa.certification-profile-execution-receipt.v1"
EVIDENCE_CONFIG_SCHEMA = "jaa.certification-evidence-config.v1"
PROFILE_DOMAIN = b"jaa-certification-profile-v1\0"
SELECTION_RECEIPT_DOMAIN = b"jaa-certification-profile-selection-receipt-v1\0"
EXECUTION_RECEIPT_DOMAIN = b"jaa-certification-profile-execution-receipt-v1\0"
EVIDENCE_CONTENT_DOMAIN = b"jaa-certification-evidence-content-v1\0"
HEX_64 = re.compile(r"[0-9a-f]{64}")
EXACT_SOURCE_GIT_REVISION = "974b41a566fd3fb95abc12827093ed681d87b31c"
EXACT_SOURCE_TREE = "212fea4b7a4924dbb3f1f7ebc30445953ddf1d51"
PINNED_LINUX_TOOL_SHA256 = {
    "/usr/bin/unshare": (
        "978a4aec5a404ad0a05faac981df501d4b7eb0c5a3ad9c1a7b929a0bfd84f6c8"
    ),
    "/usr/sbin/ip": (
        "19d7990bf9e818121a7423179611ac59be9d37b3f21b3cb9249c048072a06a08"
    ),
    "/usr/bin/setpriv": (
        "9e0d70d26a02c1cb4b984ab6f49a582b7a2c3508b1063ac23adc60073292ae7e"
    ),
}


class CertificationProfileError(RuntimeError):
    """The profile or one of its evidence/test bindings is invalid."""


JAA09_TESTS = (
    "test_jaa09_independent_acceptance.py",
    "test_jaa09_negative_controls.py",
    "test_jaa09_real_vacancy_acceptance.py",
    "test_jaa09_real_vacancy_negative_controls.py",
)

JAA10_TESTS = (
    "test_jaa10_authenticated_time_witness.py",
    "test_jaa10_authenticated_time_witness_negative_controls.py",
    "test_jaa10_certification_candidate_compiler.py",
    "test_jaa10_certification_candidate_compiler_negative_controls.py",
    "test_jaa10_external_observation_acquisition.py",
    "test_jaa10_external_observation_acquisition_negative_controls.py",
    "test_jaa10_external_time_attestation.py",
    "test_jaa10_external_time_attestation_negative_controls.py",
    "test_jaa10_frozen_replay_pair_recorder.py",
    "test_jaa10_frozen_replay_pair_recorder_negative_controls.py",
    "test_jaa10_full_submit_cohort.py",
    "test_jaa10_full_submit_cohort_negative_controls.py",
    "test_jaa10_hard_metrics_evaluation.py",
    "test_jaa10_hard_metrics_evaluation_negative_controls.py",
    "test_jaa10_hard_metrics_full_submit_integration.py",
    "test_jaa10_hard_metrics_full_submit_integration_negative_controls.py",
    "test_jaa10_independent_acceptance.py",
    "test_jaa10_linux_network_namespace_witness.py",
    "test_jaa10_linux_network_namespace_witness_negative_controls.py",
    "test_jaa10_negative_controls.py",
    "test_jaa10_network_witnessed_fixture.py",
    "test_jaa10_network_witnessed_fixture_negative_controls.py",
    "test_jaa10_observation_route_manifest.py",
    "test_jaa10_observation_route_manifest_negative_controls.py",
    "test_jaa10_shadow_elapsed_cohort.py",
    "test_jaa10_shadow_elapsed_cohort_negative_controls.py",
    "test_jaa10_shadow_fixture_measures.py",
    "test_jaa10_shadow_fixture_measures_negative_controls.py",
    "test_jaa10_shadow_observation_ledger.py",
    "test_jaa10_shadow_observation_ledger_negative_controls.py",
    "test_jaa10_three_anchor_cohort_recorder.py",
    "test_jaa10_three_anchor_cohort_recorder_negative_controls.py",
)

KNOWN_TESTS = tuple(sorted((*JAA09_TESTS, *JAA10_TESTS)))

LINUX_NAMESPACE_TESTS = (
    "test_jaa10_linux_network_namespace_witness.py",
    "test_jaa10_linux_network_namespace_witness_negative_controls.py",
    "test_jaa10_network_witnessed_fixture.py",
    "test_jaa10_network_witnessed_fixture_negative_controls.py",
)

LINUX_CLOCK_TESTS = (
    "test_jaa10_shadow_elapsed_cohort.py",
    "test_jaa10_shadow_elapsed_cohort_negative_controls.py",
)

LINUX_CHROMIUM_GOLDEN_TESTS = (
    "test_jaa10_independent_acceptance.py",
)

MAC_INAPPLICABLE_TESTS = tuple(
    sorted(
        (
            *LINUX_NAMESPACE_TESTS,
            *LINUX_CLOCK_TESTS,
            *LINUX_CHROMIUM_GOLDEN_TESTS,
        )
    )
)

LINUX_ONLY_CAPABILITY = "linux_private_network_namespace_with_pinned_tools"
LINUX_ONLY_REASON = (
    "requires Linux /proc plus pinned unshare, ip and setpriv binaries, a "
    "private network namespace, and the retained Linux Chromium identity"
)
LINUX_CLOCK_CAPABILITY = "linux_proc_clock_boottime_witness"
LINUX_CLOCK_REASON = (
    "requires Linux /proc boot identity and CLOCK_BOOTTIME for a same-boot "
    "elapsed-time witness"
)
LINUX_CHROMIUM_GOLDEN_CAPABILITY = "linux_chromium_frozen_render_identity"
LINUX_CHROMIUM_GOLDEN_REASON = (
    "executes the frozen browser workflow whose screenshot identity was fixed "
    "against Linux Chromium and is not cross-platform render-stable"
)


def _mac_exclusion_requirement(test: str) -> tuple[str, str, tuple[str, ...], bool]:
    if test in LINUX_NAMESPACE_TESTS:
        return (
            LINUX_ONLY_CAPABILITY,
            LINUX_ONLY_REASON,
            (
                "career_automation/linux_network_namespace_witness.py",
                "career_automation/network_witnessed_fixture.py",
            ),
            True,
        )
    if test in LINUX_CLOCK_TESTS:
        return (
            LINUX_CLOCK_CAPABILITY,
            LINUX_CLOCK_REASON,
            ("career_automation/shadow_elapsed_cohort.py",),
            False,
        )
    if test in LINUX_CHROMIUM_GOLDEN_TESTS:
        return (
            LINUX_CHROMIUM_GOLDEN_CAPABILITY,
            LINUX_CHROMIUM_GOLDEN_REASON,
            (
                "career_automation/browser_workflows.py",
                "career_automation/shadow_certification.py",
            ),
            False,
        )
    raise CertificationProfileError(f"unclassified Mac-inapplicable test: {test}")

REQUIRED_EVIDENCE_IDS = frozenset(
    {
        "jaa09_exact_corpus",
        "jaa10_external_control",
        "jaa10_exact_source_certificate",
        "jaa10_linux_historical_evidence",
    }
)

# The exact imported corpus identity.  The config must still state both hashes;
# these constants prevent a caller from substituting a different corpus.
JAA09_CORPUS_INVENTORY_SHA256 = (
    "f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
)
JAA09_CORPUS_MANIFEST_SHA256 = (
    "4f6cc0f06454867357ad93fc0c9c9e883b42ab050518d1a3bc9f4861cec75ced"
)
JAA10_EXACT_SOURCE_CERTIFICATE_SHA256 = (
    "72b27f845cd54b7c9ba2e70485623a3cffbc1cee7636c292fd50e0b0352f2a68"
)
JAA10_LINUX_HISTORICAL_EVIDENCE_SHA256S = frozenset(
    {
        "abc0f6418f536b9a49b8f7b07afbf46f317268d77967d5f6b442bdb75daaa290",
        "bf25551974f81b78e33431ba0a66c8ae8747904b07308b355726807747aca9fb",
        "587f7fb25a8bb9de0fd9fee69bc7348022bea66fd9fe29981c1bde172e72c7d7",
        "b6cba6ba5ac6769a8f0611f1fa6ad474d512e5e5d61680120504e14de3360c82",
        "8e143021771ca1bd25389f28386992fae9583bac8521d191a8646ae2fcc7af88",
        "01c8c98b292e4634f11fe685f703d717006dfb4cfdb9ed1e0e1f11b8c0e6fdc6",
    }
)
JAA10_LINUX_HISTORICAL_REVISIONS = (
    "01c4417c0301d69c2303f8f2d585acd6ede9a74c",
    "3d239d40ac7a74f6f390e231d967ed85dca4e4d7",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _domain_hash(domain: bytes, value: object) -> str:
    payload = _canonical_bytes(value)
    digest = hashlib.sha256(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise CertificationProfileError(f"evidence is not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    after = path.stat(follow_symlinks=False)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise CertificationProfileError(f"evidence mutated while hashing: {path}")
    return digest.hexdigest()


def _absolute_lexical_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or "\0" in os.fspath(path):
        raise CertificationProfileError(f"{label} must be an absolute directory")
    if "/home/gutua" in os.fspath(path):
        raise CertificationProfileError(f"{label} must not use implicit /home/gutua")
    if path.is_symlink():
        raise CertificationProfileError(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CertificationProfileError(f"{label} does not exist: {path}") from exc
    if resolved != path or not path.is_dir():
        raise CertificationProfileError(f"{label} must be lexical and existing: {path}")
    return path


def _absolute_lexical_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or "\0" in os.fspath(path):
        raise CertificationProfileError(f"{label} must be an absolute file")
    if "/home/gutua" in os.fspath(path):
        raise CertificationProfileError(f"{label} must not use implicit /home/gutua")
    if path.is_symlink():
        raise CertificationProfileError(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CertificationProfileError(f"{label} does not exist: {path}") from exc
    if resolved != path or not path.is_file():
        raise CertificationProfileError(f"{label} must be lexical and existing: {path}")
    return path


def _parse_sha256_manifest(
    raw: bytes, *, absolute_prefix: str | None = None
) -> dict[str, str]:
    entries: dict[str, str] = {}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CertificationProfileError("evidence manifest is not UTF-8") from exc
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            raise CertificationProfileError(
                f"invalid manifest line {line_number}; expected sha256, two spaces, path"
            )
        digest, name = match.groups()
        if absolute_prefix is not None:
            prefix = absolute_prefix.rstrip("/") + "/"
            if not name.startswith(prefix):
                raise CertificationProfileError(
                    f"manifest path is outside its declared absolute prefix: {name}"
                )
            name = name[len(prefix) :]
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in name
        ):
            raise CertificationProfileError(f"invalid manifest path: {name}")
        if name in entries:
            raise CertificationProfileError(f"duplicate manifest path: {name}")
        entries[name] = digest
    if not entries:
        raise CertificationProfileError("evidence manifest is empty")
    return entries


@dataclass(frozen=True, slots=True)
class EvidenceHook:
    evidence_id: str
    root: Path
    manifest: Path
    expected_manifest_sha256: str
    expected_content_sha256: str
    required_paths: tuple[str, ...]
    manifest_path_prefix: str | None = None

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> "EvidenceHook":
        expected_keys = {
            "evidence_id",
            "root",
            "manifest",
            "expected_manifest_sha256",
            "expected_content_sha256",
            "required_paths",
            "manifest_path_prefix",
        }
        if set(value) != expected_keys:
            raise CertificationProfileError("evidence hook keys are not exact")
        evidence_id = value["evidence_id"]
        required_paths = value["required_paths"]
        if not isinstance(evidence_id, str) or not evidence_id:
            raise CertificationProfileError("evidence_id is invalid")
        if (
            not isinstance(required_paths, list)
            or not required_paths
            or not all(isinstance(item, str) and item for item in required_paths)
            or len(set(required_paths)) != len(required_paths)
        ):
            raise CertificationProfileError("required_paths is invalid")
        for key in ("expected_manifest_sha256", "expected_content_sha256"):
            if not isinstance(value[key], str) or HEX_64.fullmatch(value[key]) is None:
                raise CertificationProfileError(f"{key} is invalid")
        manifest_path_prefix = value["manifest_path_prefix"]
        if manifest_path_prefix is not None:
            if (
                not isinstance(manifest_path_prefix, str)
                or not manifest_path_prefix.startswith("/")
                or "/home/gutua" in manifest_path_prefix
                or "\0" in manifest_path_prefix
            ):
                raise CertificationProfileError("manifest_path_prefix is invalid")
        return cls(
            evidence_id=evidence_id,
            root=Path(value["root"]),
            manifest=Path(value["manifest"]),
            expected_manifest_sha256=value["expected_manifest_sha256"],
            expected_content_sha256=value["expected_content_sha256"],
            required_paths=tuple(sorted(required_paths)),
            manifest_path_prefix=manifest_path_prefix,
        )


def _validate_evidence_hook(hook: EvidenceHook) -> dict[str, object]:
    root = _absolute_lexical_directory(hook.root, f"{hook.evidence_id} root")
    manifest = _absolute_lexical_file(
        hook.manifest, f"{hook.evidence_id} manifest"
    )
    root_before = root.stat(follow_symlinks=False)
    manifest_file_sha256 = _file_sha256(manifest)
    manifest_raw = manifest.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if manifest_sha256 != manifest_file_sha256:
        raise CertificationProfileError(
            f"{hook.evidence_id} manifest mutated while validating"
        )
    if manifest_sha256 != hook.expected_manifest_sha256:
        raise CertificationProfileError(
            f"{hook.evidence_id} manifest hash does not match expected identity"
        )
    entries = _parse_sha256_manifest(
        manifest_raw, absolute_prefix=hook.manifest_path_prefix
    )
    if tuple(sorted(entries)) != hook.required_paths:
        raise CertificationProfileError(
            f"{hook.evidence_id} manifest paths differ from required_paths"
        )

    actual_files: set[str] = set()
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise CertificationProfileError(
                f"{hook.evidence_id} contains a symlink: {candidate}"
            )
        if candidate.is_file():
            actual_files.add(candidate.relative_to(root).as_posix())
    if actual_files != set(entries):
        raise CertificationProfileError(
            f"{hook.evidence_id} root inventory differs from its manifest"
        )

    validated_entries: list[dict[str, str]] = []
    for relative_path in sorted(entries):
        path = root.joinpath(*PurePosixPath(relative_path).parts)
        actual_sha256 = _file_sha256(path)
        if actual_sha256 != entries[relative_path]:
            raise CertificationProfileError(
                f"{hook.evidence_id} evidence hash mismatch: {relative_path}"
            )
        validated_entries.append(
            {"path": relative_path, "sha256": actual_sha256}
        )
    content_sha256 = _domain_hash(EVIDENCE_CONTENT_DOMAIN, validated_entries)
    if content_sha256 != hook.expected_content_sha256:
        raise CertificationProfileError(
            f"{hook.evidence_id} content identity does not match expected identity"
        )

    if hook.evidence_id == "jaa09_exact_corpus":
        inventory = entries.get("corpus_inventory.json")
        if inventory != JAA09_CORPUS_INVENTORY_SHA256:
            raise CertificationProfileError("JAA-09 corpus inventory identity is wrong")
        if manifest_sha256 != JAA09_CORPUS_MANIFEST_SHA256:
            raise CertificationProfileError("JAA-09 corpus manifest identity is wrong")
    if hook.evidence_id == "jaa10_exact_source_certificate":
        if JAA10_EXACT_SOURCE_CERTIFICATE_SHA256 not in entries.values():
            raise CertificationProfileError(
                "JAA-10 exact-source evidence lacks its independent certificate"
            )
    if hook.evidence_id == "jaa10_linux_historical_evidence":
        missing = sorted(
            JAA10_LINUX_HISTORICAL_EVIDENCE_SHA256S - set(entries.values())
        )
        if missing:
            raise CertificationProfileError(
                f"historical Linux evidence is incomplete: {missing}"
            )

    root_after = root.stat(follow_symlinks=False)
    root_identity_before = (
        root_before.st_dev,
        root_before.st_ino,
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    )
    root_identity_after = (
        root_after.st_dev,
        root_after.st_ino,
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    )
    if root_identity_before != root_identity_after:
        raise CertificationProfileError(
            f"{hook.evidence_id} root mutated while validating"
        )

    return {
        "evidence_id": hook.evidence_id,
        "root": str(root),
        "manifest": str(manifest),
        "manifest_sha256": manifest_sha256,
        "content_sha256": content_sha256,
        "entries": validated_entries,
    }


@dataclass(frozen=True, slots=True)
class HostCapabilities:
    system: str
    machine: str
    has_proc: bool
    unshare_sha256: str | None
    ip_sha256: str | None
    setpriv_sha256: str | None

    @property
    def linux_namespace_witness(self) -> bool:
        return (
            self.system == "Linux"
            and self.has_proc
            and self.unshare_sha256 == PINNED_LINUX_TOOL_SHA256["/usr/bin/unshare"]
            and self.ip_sha256 == PINNED_LINUX_TOOL_SHA256["/usr/sbin/ip"]
            and self.setpriv_sha256 == PINNED_LINUX_TOOL_SHA256["/usr/bin/setpriv"]
        )

    def document(self) -> dict[str, object]:
        return {
            "system": self.system,
            "machine": self.machine,
            "has_proc": self.has_proc,
            "pinned_tools": {
                "/usr/bin/unshare": self.unshare_sha256,
                "/usr/sbin/ip": self.ip_sha256,
                "/usr/bin/setpriv": self.setpriv_sha256,
            },
            "capabilities": {
                LINUX_ONLY_CAPABILITY: self.linux_namespace_witness,
            },
        }


def detect_host_capabilities() -> HostCapabilities:
    def tool_hash(path: str) -> str | None:
        candidate = Path(path)
        if not candidate.is_file() or candidate.is_symlink():
            return None
        return _file_sha256(candidate)

    return HostCapabilities(
        system=platform.system(),
        machine=platform.machine(),
        has_proc=Path("/proc/self/status").is_file(),
        unshare_sha256=tool_hash("/usr/bin/unshare"),
        ip_sha256=tool_hash("/usr/sbin/ip"),
        setpriv_sha256=tool_hash("/usr/bin/setpriv"),
    )


def _git(repository_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _source_identity(repository_root: Path) -> dict[str, object]:
    status = _git(
        repository_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status:
        raise CertificationProfileError(
            "dirty or untracked source cannot enter a certification profile"
        )
    git_revision = _git(repository_root, "rev-parse", "HEAD")
    tree = _git(repository_root, "rev-parse", "HEAD^{tree}")
    exact_certified_source = (
        git_revision == EXACT_SOURCE_GIT_REVISION and tree == EXACT_SOURCE_TREE
    )
    ancestry = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "merge-base",
            "--is-ancestor",
            EXACT_SOURCE_GIT_REVISION,
            git_revision,
        ],
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        raise CertificationProfileError(
            "current source is not a descendant of the independently certified import"
        )
    return {
        "git_revision": git_revision,
        "tree": tree,
        "worktree_clean_including_untracked": True,
        "certified_base_git_revision": EXACT_SOURCE_GIT_REVISION,
        "certified_base_tree": EXACT_SOURCE_TREE,
        "certified_base_is_ancestor": True,
        "exact_source_certificate_applies_to_current_source": exact_certified_source,
        "post_import_independent_certification_required": not exact_certified_source,
    }


def _validate_repository_tests(repository_root: Path) -> None:
    _absolute_lexical_directory(repository_root, "repository root")
    discovered = {
        path.name
        for path in repository_root.iterdir()
        if path.is_file()
        and (path.name.startswith("test_jaa09") or path.name.startswith("test_jaa10"))
        and path.suffix == ".py"
    }
    expected = set(KNOWN_TESTS)
    unknown = sorted(discovered - expected)
    missing = sorted(expected - discovered)
    if unknown:
        raise CertificationProfileError(f"unknown JAA tests: {unknown}")
    if missing:
        raise CertificationProfileError(f"known JAA tests are missing: {missing}")


def build_profile(
    repository_root: Path,
    hooks: Sequence[EvidenceHook],
    capabilities: HostCapabilities | None = None,
) -> dict[str, object]:
    """Build and validate a deterministic profile; perform no test execution."""

    _validate_repository_tests(repository_root)
    capability = capabilities or detect_host_capabilities()
    hook_ids = [hook.evidence_id for hook in hooks]
    if len(hook_ids) != len(set(hook_ids)) or set(hook_ids) != REQUIRED_EVIDENCE_IDS:
        raise CertificationProfileError(
            "evidence hooks must be the exact required JAA-09/JAA-10 set"
        )
    evidence = [
        _validate_evidence_hook(hook)
        for hook in sorted(hooks, key=lambda item: item.evidence_id)
    ]

    source = _source_identity(repository_root)

    if capability.system == "Linux" and capability.linux_namespace_witness:
        applicable = list(KNOWN_TESTS)
        exclusions: list[dict[str, object]] = []
        profile_kind = "linux-full"
    elif capability.system == "Darwin":
        applicable = sorted(set(KNOWN_TESTS) - set(MAC_INAPPLICABLE_TESTS))
        historical = next(
            item
            for item in evidence
            if item["evidence_id"] == "jaa10_linux_historical_evidence"
        )
        exclusions = []
        for test in MAC_INAPPLICABLE_TESTS:
            capability_name, reason, retained_nodes, has_historical_evidence = (
                _mac_exclusion_requirement(test)
            )
            exclusions.append(
                {
                    "test": test,
                    "capability": capability_name,
                    "reason": reason,
                    "historical_evidence_available": has_historical_evidence,
                    "historical_evidence_id": (
                        historical["evidence_id"] if has_historical_evidence else None
                    ),
                    "historical_manifest_sha256": (
                        historical["manifest_sha256"]
                        if has_historical_evidence
                        else None
                    ),
                    "historical_content_sha256": (
                        historical["content_sha256"]
                        if has_historical_evidence
                        else None
                    ),
                    "historical_source_revisions": (
                        list(JAA10_LINUX_HISTORICAL_REVISIONS)
                        if has_historical_evidence
                        else []
                    ),
                    "current_source_linux_execution_verified": False,
                    "current_source_linux_execution_required": True,
                    "certified_by_this_profile": False,
                    "test_source_sha256": _file_sha256(repository_root / test),
                    "retained_source_nodes": [
                        {
                            "path": path,
                            "sha256": _file_sha256(repository_root / path),
                        }
                        for path in retained_nodes
                    ],
                }
            )
        profile_kind = "mac-with-retained-linux-evidence"
    else:
        raise CertificationProfileError(
            "unsupported host or Linux host lacks the exact pinned witness capability"
        )

    profile: dict[str, object] = {
        "schema_version": PROFILE_SCHEMA,
        "profile_kind": profile_kind,
        "scope": ["JAA-09", "JAA-10"],
        "source": source,
        "platform": capability.document(),
        "applicable_tests": applicable,
        "linux_only_exclusions": exclusions,
        "evidence": evidence,
        "claims": {
            "defines_test_selection_only": True,
            "product_certified": False,
            "jaa11_certified": False,
            "skipped_product_test_certified": False,
            "test_execution_completed": False,
            "exact_source_certificate_applies_to_current_source": source[
                "exact_source_certificate_applies_to_current_source"
            ],
            "post_import_independent_certification_required": source[
                "post_import_independent_certification_required"
            ],
            "current_source_linux_execution_verified": (
                capability.linux_namespace_witness
            ),
        },
    }
    profile["profile_sha256"] = _domain_hash(PROFILE_DOMAIN, profile)
    return profile


def selection_receipt(profile: Mapping[str, object]) -> dict[str, object]:
    profile_sha256 = profile.get("profile_sha256")
    if not isinstance(profile_sha256, str) or HEX_64.fullmatch(profile_sha256) is None:
        raise CertificationProfileError("profile identity is invalid")
    receipt: dict[str, object] = {
        "schema_version": SELECTION_RECEIPT_SCHEMA,
        "profile_sha256": profile_sha256,
        "source": profile["source"],
        "platform": profile["platform"],
        "evidence_identities": [
            {
                "evidence_id": item["evidence_id"],
                "manifest_sha256": item["manifest_sha256"],
                "content_sha256": item["content_sha256"],
            }
            for item in profile["evidence"]  # type: ignore[index]
        ],
        "claims": {
            "selection_validated": True,
            "tests_executed": False,
            "product_certified": False,
            "jaa11_certified": False,
            "retained_linux_tests_certified_by_this_receipt": False,
        },
    }
    receipt["receipt_sha256"] = _domain_hash(SELECTION_RECEIPT_DOMAIN, receipt)
    return receipt


def bind_execution_results(
    profile: Mapping[str, object], outcomes: Mapping[str, str]
) -> dict[str, object]:
    """Bind file-level outcomes, rejecting skips and unclassified non-passes."""

    applicable = profile.get("applicable_tests")
    if not isinstance(applicable, list) or not all(
        isinstance(test, str) for test in applicable
    ):
        raise CertificationProfileError("profile applicable_tests is invalid")
    if set(outcomes) != set(applicable):
        unknown = sorted(set(outcomes) - set(applicable))
        missing = sorted(set(applicable) - set(outcomes))
        raise CertificationProfileError(
            f"execution outcomes are not exact; unknown={unknown}, missing={missing}"
        )
    non_passes = {
        test: status
        for test, status in outcomes.items()
        if status != "passed"
    }
    if non_passes:
        raise CertificationProfileError(
            f"unclassified failure, error, or skip is forbidden: {non_passes}"
        )
    receipt: dict[str, object] = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "profile_sha256": profile["profile_sha256"],
        "source": profile["source"],
        "platform": profile["platform"],
        "evidence": profile["evidence"],
        "outcomes": [
            {"test": test, "status": "passed"} for test in sorted(outcomes)
        ],
        "claims": {
            "all_applicable_profile_tests_passed": True,
            "product_certified": False,
            "jaa11_certified": False,
            "excluded_linux_tests_certified_by_this_receipt": False,
        },
    }
    receipt["receipt_sha256"] = _domain_hash(EXECUTION_RECEIPT_DOMAIN, receipt)
    return receipt


def load_evidence_config(path: Path) -> list[EvidenceHook]:
    _absolute_lexical_file(path, "evidence config")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationProfileError("evidence config is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "hooks"}:
        raise CertificationProfileError("evidence config keys are not exact")
    if value["schema_version"] != EVIDENCE_CONFIG_SCHEMA:
        raise CertificationProfileError("evidence config schema is unsupported")
    hooks = value["hooks"]
    if not isinstance(hooks, list):
        raise CertificationProfileError("evidence config hooks must be a list")
    return [EvidenceHook.from_document(item) for item in hooks]


def _write_canonical(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise CertificationProfileError("output must be a new absolute path")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, _canonical_bytes(value) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--evidence-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        hooks = load_evidence_config(args.evidence_config)
        profile = build_profile(args.repository_root, hooks)
        bundle = {
            "profile": profile,
            "selection_receipt": selection_receipt(profile),
        }
        _write_canonical(args.output, bundle)
    except (CertificationProfileError, subprocess.CalledProcessError) as exc:
        print(f"certification profile refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
