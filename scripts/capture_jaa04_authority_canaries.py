#!/usr/bin/env python3
"""Capture exactly three typed JAA-04 ATS canaries through the production sidecar."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import (  # noqa: E402
    ATS_AUTHORITY_CANARIES, PortableAuthorityRetriever, RawResponseCache,
    ScraplingPublicRetriever,
)
from career_automation.public_access import PublicAccessPolicy  # noqa: E402


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def capture(destination: Path, access_policy: PublicAccessPolicy) -> None:
    """Publish three self-contained canaries, never a dossier corpus or receipt."""
    if destination.exists():
        raise RuntimeError("canary destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="jaa04-canaries-", dir=destination.parent))
    cache = RawResponseCache(stage / ".raw")
    try:
        transport = ScraplingPublicRetriever(
            cache,
            root=ROOT,
            access_policy=access_policy,
        )
        retriever = PortableAuthorityRetriever(cache, retriever=transport)
        for record in ATS_AUTHORITY_CANARIES:
            task = SimpleNamespace(job_key=record.job_key, company=record.company,
                                   title=record.title, url=record.admitted_url)
            citations, plan = retriever.retrieve_plan(task)
            captures = []
            for citation in citations:
                raw = cache.resolve(citation.raw_response_ref, citation.content_sha256)
                capture_row = vars(citation).copy()
                capture_row.update({
                    "sidecar_raw_response_ref": citation.raw_response_ref,
                    "raw_response_ref": "embedded:raw_response_base64",
                    "raw_response_encoding": "base64",
                    "raw_response_base64": base64.b64encode(raw).decode("ascii"),
                })
                captures.append(capture_row)
            artifact = {
                "schema_version": "jaa04.typed-authority-canary.v1",
                "admitted_record": vars(record),
                "captures": captures,
                "source_plan": plan,
            }
            filename = record.job_key.split(":", 1)[0] + ".json"
            (stage / filename).write_bytes(_canonical(artifact))
        shutil.rmtree(stage / ".raw")
        files = sorted(path.name for path in stage.iterdir() if path.is_file())
        if files != ["ashby.json", "greenhouse.json", "workable.json"]:
            raise RuntimeError("canary capture must produce exactly three artifacts")
        os.rename(stage, destination)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--access-policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        access_policy = PublicAccessPolicy.load(args.access_policy.resolve())
        capture(args.destination.resolve(), access_policy)
    except Exception as exc:
        print(f"JAA-04 authority canaries: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "artifacts": 3,
                      "destination": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
