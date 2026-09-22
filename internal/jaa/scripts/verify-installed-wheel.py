#!/usr/bin/env python3
"""Smoke-check installed JAA and Market wheels from outside their source checkouts."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.resources
import os
import platform
import subprocess
import sys
from pathlib import Path


DISTRIBUTION = "job-application-automation"
MARKET_DISTRIBUTION = "market-aligner"
PACKAGES = (
    "baseline_adoption",
    "career_automation",
    "llm",
    "profiler",
    "scraper",
    "scraper.adapters",
    "skeleton",
)
MODULES = ("tracked_source_revision",)
OPERATIONAL_MODULES = (
    "career_automation.application_archive",
    "career_automation.application_sanity_review",
    "career_automation.browser_executor",
    "career_automation.candidate_release_gate",
    "career_automation.current_time",
    "career_automation.event_receipts",
    "career_automation.ats_application_authority",
    "career_automation.handoff_admission",
    "career_automation.handoff_cli",
    "career_automation.market_aligner_handoff",
    "career_automation.protected_corpus_binding",
    "career_automation.production_ats_executor",
    "career_automation.production_queue",
    "career_automation.production_runner",
    "career_automation.runtime_compatibility",
    "career_automation.network_witnessed_fixture",
)
MARKET_MODULES = (
    "market_aligner.applications.events",
    "market_aligner.applications.contracts",
)
RESOURCES = (
    ("career_automation", "fixtures/jaa04_authority_canaries/greenhouse.json"),
    ("llm", "schemas/job_extract.json"),
    ("scraper", "fixtures/jobkorea_listing.json"),
    ("skeleton", "config.additional.yaml"),
    ("skeleton", "fixtures/jobs_20.jsonl"),
)
RESOURCE_HASHES = (
    (
        "career_automation",
        "fixtures/market-aligner-v1-vectors.json",
        "421d39504c4828c928389d5c30c2147fb7c01249b299972a11e204e956350160",
    ),
)


def verify(source_roots: tuple[Path, ...]) -> None:
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
        raise SystemExit("installed-wheel verification requires exact CPython 3.12.13")
    distribution = importlib.metadata.distribution(DISTRIBUTION)
    if distribution.version != "1.0.0":
        raise SystemExit(f"unexpected {DISTRIBUTION} version: {distribution.version}")
    installed_files = {
        Path(str(file)).as_posix() for file in (distribution.files or ())
    }
    if "tracked_source_revision.py" not in installed_files:
        raise SystemExit("wheel omits tracked_source_revision.py")
    installed_source_revision = Path(
        distribution.locate_file("tracked_source_revision.py")
    ).resolve()
    if not installed_source_revision.is_file():
        raise SystemExit("installed tracked_source_revision.py is unavailable")
    installation_root = Path(distribution.locate_file("")).resolve()

    for module_name in (*PACKAGES, *MODULES, *OPERATIONAL_MODULES):
        module = importlib.import_module(module_name)
        module_path = Path(module.__file__ or "").resolve()
        if any(module_path.is_relative_to(root) for root in source_roots):
            raise SystemExit(f"{module_name} resolved from a source tree")
        if not module_path.is_relative_to(installation_root):
            raise SystemExit(f"{module_name} resolved outside the installed environment")
        if module_name == "tracked_source_revision" and module_path != installed_source_revision:
            raise SystemExit("tracked_source_revision resolved outside the installed wheel")

    from career_automation.protected_corpus_binding import installed_distribution_manifest

    installed_distribution_manifest()

    market_distribution = importlib.metadata.distribution(MARKET_DISTRIBUTION)
    if market_distribution.version != "0.1.0.dev0":
        raise SystemExit(
            f"unexpected {MARKET_DISTRIBUTION} version: {market_distribution.version}"
        )
    market_root = Path(market_distribution.locate_file("")).resolve()
    for module_name in MARKET_MODULES:
        module = importlib.import_module(module_name)
        module_path = Path(module.__file__ or "").resolve()
        if any(module_path.is_relative_to(root) for root in source_roots):
            raise SystemExit(f"{module_name} resolved from a source tree")
        if not module_path.is_relative_to(market_root):
            raise SystemExit(
                f"{module_name} resolved outside the installed {MARKET_DISTRIBUTION} root"
            )

    installed_distribution_manifest(
        distribution_name=MARKET_DISTRIBUTION, expected_version="0.1.0.dev0"
    )

    entry_points = {
        entry.name: entry for entry in distribution.entry_points if entry.group == "console_scripts"
    }
    expected = {
        "jaa-baseline",
        "jaa-document-assurance",
        "jaa-handoff",
        "jaa-lifecycle",
        "jaa-official-cohort",
    }
    if set(entry_points) != expected:
        raise SystemExit(f"console entry points differ: {sorted(entry_points)}")
    market_entries = {
        entry.name: entry for entry in market_distribution.entry_points
        if entry.group == "console_scripts"
    }
    if set(market_entries) != {"market-aligner"}:
        raise SystemExit("Market console entry points differ")
    entry_points.update(market_entries)
    smoke_environment = os.environ.copy()
    smoke_environment.pop("PYTHONHOME", None)
    smoke_environment.pop("PYTHONPATH", None)
    for entry in entry_points.values():
        entry.load()
        command = Path(sys.executable).parent / entry.name
        if not command.is_file():
            raise SystemExit(f"installed console script is missing: {entry.name}")
        completed = subprocess.run(
            (str(command), "--help"),
            check=False,
            capture_output=True,
            cwd=Path.cwd(),
            env=smoke_environment,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"installed console script --help failed: {entry.name}: "
                f"{completed.stderr.strip()}"
            )
    for package, relative in RESOURCES:
        resource = importlib.resources.files(package).joinpath(relative)
        if not resource.is_file() or not resource.read_bytes():
            raise SystemExit(f"wheel resource is missing: {package}/{relative}")
    for package, relative, expected_sha256 in RESOURCE_HASHES:
        resource = importlib.resources.files(package).joinpath(relative)
        if not resource.is_file():
            raise SystemExit(f"wheel resource is missing: {package}/{relative}")
        actual_sha256 = hashlib.sha256(resource.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise SystemExit(
                f"wheel resource digest differs: {package}/{relative}: {actual_sha256}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, action="append", required=True)
    args = parser.parse_args()
    verify(tuple(path.resolve() for path in args.source_root))
    print(f"installed wheel verified: {DISTRIBUTION}==1.0.0, {MARKET_DISTRIBUTION}==0.1.0.dev0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
