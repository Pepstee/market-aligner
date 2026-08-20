#!/usr/bin/env python3
"""Atomically replace JAA-04 with a newly acquired authentic corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from capture_jaa_04 import ROOT, capture, external_runtime_path
from career_automation.corpus_publication import publish_by_pointer, validate_inventory
from career_automation.employer_research import RawResponseCache, load_frozen_dossiers
from career_automation.public_access import PublicAccessPolicy
from career_automation.seed_cohort import hydrate_seed


def _capture_input(
    queue_snapshot: Path,
    workspace: Path,
    *,
    maximum_routes: int,
    timeout_seconds: int,
    access_policy: PublicAccessPolicy,
) -> Path:
    """Turn a checked v1 seed into v2 evidence without weakening capture."""
    if queue_snapshot.suffix.casefold() != ".json":
        return queue_snapshot
    payload = json.loads(queue_snapshot.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "jaa04.admitted-queue.v1":
        return queue_snapshot
    admission = workspace / "admission"
    prepared = admission / "official-admitted-queue-v2.json"
    if prepared.exists():
        existing = json.loads(prepared.read_text(encoding="utf-8"))
        seed = existing.get("seed")
        expected = hashlib.sha256(queue_snapshot.read_bytes()).hexdigest()
        if not isinstance(seed, dict) or seed.get("sha256") != expected:
            raise RuntimeError("prepared v2 queue belongs to a different checked seed")
        return prepared
    hydrate_seed(
        queue_snapshot,
        prepared,
        admission / "raw",
        maximum_routes=maximum_routes,
        timeout_seconds=timeout_seconds,
        access_policy=access_policy,
    )
    return prepared

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-snapshot", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True,
                        help="stable external in-flight acquisition workspace")
    parser.add_argument("--corpus", type=Path, required=True,
                        help="external atomic pointer for the certified corpus")
    parser.add_argument("--maximum-routes", type=int, default=12)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    parser.add_argument("--access-policy", type=Path, required=True,
                        help="external human terms-review attestations")
    args = parser.parse_args()
    destination = external_runtime_path(args.corpus, label="corpus destination")
    workspace = external_runtime_path(args.workspace, label="acquisition workspace")
    access_policy_path = external_runtime_path(args.access_policy, label="access policy")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fresh = Path(tempfile.mkdtemp(prefix="jaa04-authentic-", dir=destination.parent))
    fresh.rmdir()
    try:
        if args.maximum_routes < 1 or args.timeout_seconds < 1:
            raise ValueError("retrieval limits must be positive")
        access_policy = PublicAccessPolicy.load(access_policy_path)
        queue_snapshot = _capture_input(
            args.queue_snapshot.resolve(),
            workspace,
            maximum_routes=args.maximum_routes,
            timeout_seconds=args.timeout_seconds,
            access_policy=access_policy,
        )
        capture(queue_snapshot, fresh, workspace=workspace / "research",
                maximum_routes=args.maximum_routes, timeout_seconds=args.timeout_seconds,
                access_policy=access_policy)
        def validate(path: Path) -> None:
            validate_inventory(path)
            dossiers = load_frozen_dossiers(
                path / "frozen_dossiers.json",
                RawResponseCache(path / "raw"),
                strict_corpus=True,
                access_policies={access_policy.policy_sha256: access_policy},
            )
            if len(dossiers) != 30:
                raise RuntimeError("atomic publication requires exactly 30 dossiers")
        publish_by_pointer(fresh, destination, validate)
    except BaseException:
        shutil.rmtree(fresh, ignore_errors=True)
        raise
    print("JAA-04 authentic corpus rebuild: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
