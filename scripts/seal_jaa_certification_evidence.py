#!/usr/bin/env python3
"""Seal the exact external evidence hooks consumed by the JAA host profile.

The sealer copies nothing and never mutates evidence roots. It inventories each
already-transferred root, checks the pinned critical files, writes new manifests
outside those roots, validates the resulting hooks, and emits a canonical
machine-local configuration plus a non-certifying sealing receipt.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Mapping, Sequence

try:
    from scripts import jaa_certification_profile as profile
except ModuleNotFoundError:  # Direct execution sets sys.path[0] to scripts/.
    import jaa_certification_profile as profile  # type: ignore[no-redef]


SEAL_RECEIPT_SCHEMA = "jaa.certification-evidence-seal.v1"
SEAL_RECEIPT_DOMAIN = b"jaa-certification-evidence-seal-v1\0"

EXTERNAL_CONTROL_FILES = {
    (
        "jaa-single-codex-20260729/"
        "jaa07-post-review-repair-evaluator.log"
    ): "5cf1f1f5bcee57aaf8a517edb734cf9dadf1802e44f831defd105418c41ef1fe",
    (
        "jaa-single-codex-20260729/"
        "JAA10_FROZEN_REPLAY_PAIR_PRIMARY_95caa725/replay-pair.json"
    ): "0b278e63b95fd3031d0f6b9181f7e5d783c08052a1a7abd591dbc1467662b786",
    (
        "jaa-post-interval-20260803/"
        "jaa10-full-submit-cohort-v2/evidence/cohort.json"
    ): "8fa735558bcb57845663b6c436cbfc922c422b9f4abef02232089e30e169a5ba",
}

EXACT_SOURCE_CERTIFICATE_FILES = {
    "opus-jaa10-exact-source-certification-raw.json": (
        profile.JAA10_EXACT_SOURCE_CERTIFICATE_SHA256
    )
}

LINUX_HISTORICAL_FILES = {
    "FABLE_JAA10_OS_NETWORK_WITNESS_EXACT_SOURCE_ACCEPTANCE.md": (
        "abc0f6418f536b9a49b8f7b07afbf46f317268d77967d5f6b442bdb75daaa290"
    ),
    "fable-jaa10-network-witnessed-fixture-exact-source-raw.json": (
        "bf25551974f81b78e33431ba0a66c8ae8747904b07308b355726807747aca9fb"
    ),
    "fable-jaa10-os-network-witness-exact-source-raw.json": (
        "587f7fb25a8bb9de0fd9fee69bc7348022bea66fd9fe29981c1bde172e72c7d7"
    ),
    "jaa10-network-witnessed-fixture-runtime-v3-3d239d4.ACCEPTED.v3.json": (
        "b6cba6ba5ac6769a8f0611f1fa6ad474d512e5e5d61680120504e14de3360c82"
    ),
    "sonnet-jaa10-network-witnessed-fixture-exact-source-review-raw.json": (
        "8e143021771ca1bd25389f28386992fae9583bac8521d191a8646ae2fcc7af88"
    ),
    "sonnet-jaa10-os-network-witness-exact-source-review-raw.json": (
        "01c8c98b292e4634f11fe685f703d717006dfb4cfdb9ed1e0e1f11b8c0e6fdc6"
    ),
}


def _file_sha256(path: Path) -> str:
    return profile._file_sha256(path)


def _lexical_directory(path: Path, label: str) -> Path:
    return profile._absolute_lexical_directory(path, label)


def _inventory(root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for candidate in sorted(root.rglob("*")):
        metadata = candidate.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise profile.CertificationProfileError(
                f"evidence contains a symlink: {candidate}"
            )
        if candidate.is_file():
            values[candidate.relative_to(root).as_posix()] = _file_sha256(candidate)
    if not values:
        raise profile.CertificationProfileError(f"evidence root is empty: {root}")
    return values


def _assert_exact_inventory(
    root: Path, expected: Mapping[str, str], label: str
) -> dict[str, str]:
    actual = _inventory(root)
    if actual != dict(expected):
        missing = sorted(set(expected) - set(actual))
        unknown = sorted(set(actual) - set(expected))
        changed = sorted(
            path
            for path in set(actual) & set(expected)
            if actual[path] != expected[path]
        )
        raise profile.CertificationProfileError(
            f"{label} inventory differs; missing={missing}, unknown={unknown}, "
            f"changed={changed}"
        )
    return actual


def _write_manifest(path: Path, entries: Mapping[str, str]) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise profile.CertificationProfileError(
            "manifest output must be a new absolute path"
        )
    payload = "".join(
        f"{digest}  {relative}\n" for relative, digest in sorted(entries.items())
    ).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _content_identity(entries: Mapping[str, str]) -> str:
    document = [
        {"path": relative, "sha256": digest}
        for relative, digest in sorted(entries.items())
    ]
    return profile._domain_hash(profile.EVIDENCE_CONTENT_DOMAIN, document)


def _hook(
    *,
    evidence_id: str,
    root: Path,
    manifest: Path,
    entries: Mapping[str, str],
    manifest_path_prefix: str | None = None,
) -> profile.EvidenceHook:
    return profile.EvidenceHook(
        evidence_id=evidence_id,
        root=root,
        manifest=manifest,
        expected_manifest_sha256=_file_sha256(manifest),
        expected_content_sha256=_content_identity(entries),
        required_paths=tuple(sorted(entries)),
        manifest_path_prefix=manifest_path_prefix,
    )


def _hook_document(hook: profile.EvidenceHook) -> dict[str, object]:
    return {
        "evidence_id": hook.evidence_id,
        "root": str(hook.root),
        "manifest": str(hook.manifest),
        "expected_manifest_sha256": hook.expected_manifest_sha256,
        "expected_content_sha256": hook.expected_content_sha256,
        "required_paths": list(hook.required_paths),
        "manifest_path_prefix": hook.manifest_path_prefix,
    }


def seal(
    *,
    corpus_root: Path,
    corpus_manifest: Path,
    corpus_manifest_prefix: str,
    external_control_root: Path,
    exact_source_certificate_root: Path,
    linux_historical_root: Path,
    output_directory: Path,
) -> dict[str, Path]:
    if (
        not output_directory.is_absolute()
        or output_directory.exists()
        or output_directory.is_symlink()
    ):
        raise profile.CertificationProfileError(
            "output directory must be a new absolute path"
        )
    output_directory.mkdir(parents=True, mode=0o700)

    corpus_root = _lexical_directory(corpus_root, "JAA-09 corpus root")
    corpus_manifest = profile._absolute_lexical_file(
        corpus_manifest, "JAA-09 corpus manifest"
    )
    if _file_sha256(corpus_manifest) != profile.JAA09_CORPUS_MANIFEST_SHA256:
        raise profile.CertificationProfileError("JAA-09 corpus manifest is not exact")
    corpus_entries = profile._parse_sha256_manifest(
        corpus_manifest.read_bytes(), absolute_prefix=corpus_manifest_prefix
    )

    external_control_root = _lexical_directory(
        external_control_root, "JAA-10 external-control root"
    )
    exact_source_certificate_root = _lexical_directory(
        exact_source_certificate_root, "JAA-10 exact-source certificate root"
    )
    linux_historical_root = _lexical_directory(
        linux_historical_root, "JAA-10 Linux historical root"
    )
    external_entries = _assert_exact_inventory(
        external_control_root, EXTERNAL_CONTROL_FILES, "external-control"
    )
    exact_entries = _assert_exact_inventory(
        exact_source_certificate_root,
        EXACT_SOURCE_CERTIFICATE_FILES,
        "exact-source certificate",
    )
    historical_entries = _assert_exact_inventory(
        linux_historical_root, LINUX_HISTORICAL_FILES, "Linux historical"
    )

    external_manifest = output_directory / "jaa10_external_control.sha256"
    exact_manifest = output_directory / "jaa10_exact_source_certificate.sha256"
    historical_manifest = output_directory / "jaa10_linux_historical_evidence.sha256"
    _write_manifest(external_manifest, external_entries)
    _write_manifest(exact_manifest, exact_entries)
    _write_manifest(historical_manifest, historical_entries)

    hooks = [
        _hook(
            evidence_id="jaa09_exact_corpus",
            root=corpus_root,
            manifest=corpus_manifest,
            entries=corpus_entries,
            manifest_path_prefix=corpus_manifest_prefix,
        ),
        _hook(
            evidence_id="jaa10_external_control",
            root=external_control_root,
            manifest=external_manifest,
            entries=external_entries,
        ),
        _hook(
            evidence_id="jaa10_exact_source_certificate",
            root=exact_source_certificate_root,
            manifest=exact_manifest,
            entries=exact_entries,
        ),
        _hook(
            evidence_id="jaa10_linux_historical_evidence",
            root=linux_historical_root,
            manifest=historical_manifest,
            entries=historical_entries,
        ),
    ]
    validated = [profile._validate_evidence_hook(hook) for hook in hooks]

    config = {
        "schema_version": profile.EVIDENCE_CONFIG_SCHEMA,
        "hooks": [_hook_document(hook) for hook in hooks],
    }
    config_path = output_directory / "evidence-config.json"
    profile._write_canonical(config_path, config)
    receipt: dict[str, object] = {
        "schema_version": SEAL_RECEIPT_SCHEMA,
        "config_sha256": _file_sha256(config_path),
        "evidence": [
            {
                "evidence_id": item["evidence_id"],
                "manifest_sha256": item["manifest_sha256"],
                "content_sha256": item["content_sha256"],
            }
            for item in validated
        ],
        "claims": {
            "evidence_transferred_and_hash_validated": True,
            "current_source_certified": False,
            "current_source_linux_execution_verified": False,
            "product_certified": False,
            "jaa11_certified": False,
        },
    }
    receipt["receipt_sha256"] = profile._domain_hash(SEAL_RECEIPT_DOMAIN, receipt)
    receipt_path = output_directory / "seal-receipt.json"
    profile._write_canonical(receipt_path, receipt)
    return {"config": config_path, "receipt": receipt_path}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--corpus-manifest", required=True, type=Path)
    parser.add_argument("--corpus-manifest-prefix", required=True)
    parser.add_argument("--external-control-root", required=True, type=Path)
    parser.add_argument("--exact-source-certificate-root", required=True, type=Path)
    parser.add_argument("--linux-historical-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        outputs = seal(**vars(args))
    except profile.CertificationProfileError as exc:
        print(f"evidence sealing refused: {exc}", file=sys.stderr)
        return 2
    for name, path in sorted(outputs.items()):
        print(f"{name}={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
