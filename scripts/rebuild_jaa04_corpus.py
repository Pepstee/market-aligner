#!/usr/bin/env python3
"""Rebuild the reviewed JAA-04 dossiers and hash envelopes from captured bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import (  # noqa: E402
    Citation, RawResponseCache, build_reconnaissance_dossier, content_hash,
    load_frozen_dossiers,
)

CAPTURE = ROOT / "career_automation/fixtures/jaa04_capture"


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()


def raw_corpus_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in (CAPTURE / "raw").rglob("*") if item.is_file()):
        digest.update(path.relative_to(CAPTURE).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> int:
    frozen_path = CAPTURE / "frozen_dossiers.json"
    manifest_path = CAPTURE / "research_manifest.json"
    old_dossiers = json.loads(frozen_path.read_text(encoding="utf-8"))["dossiers"]
    old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records_by_key = {record["job_key"]: record for record in old_manifest["records"]}
    cache = RawResponseCache(CAPTURE / "raw")
    dossiers = []
    records = []
    for old in old_dossiers:
        record = records_by_key[old["job_key"]]
        first_source = dict(old["sources"][0])
        first_source["id"] = f"source:{old['job_key']}"
        captured = Citation(**first_source)
        dossier = build_reconnaissance_dossier(
            SimpleNamespace(job_key=old["job_key"], company=record["company"],
                            title=record["role"]),
            captured, cache, observed_at=captured.captured_at,
        )
        dossier["raw_cache_root"] = "raw"
        dossiers.append(dossier)
        rebuilt = dict(record)
        rebuilt.pop("source_id", None)
        rebuilt.update({
            "source_ids": [source["id"] for source in dossier["sources"]],
            "sources": dossier["sources"],
            "source_plan": dossier["source_plan"],
        })
        records.append(rebuilt)
    frozen = {"schema_version": "jaa04.frozen-dossiers.v1", "dossiers": dossiers,
              "dossiers_hash": content_hash(dossiers)}
    manifest = {"schema_version": "jaa04.research-manifest.v2", "records": records,
                "records_hash": content_hash(records)}
    frozen_path.write_bytes(canonical(frozen))
    manifest_path.write_bytes(canonical(manifest))
    load_frozen_dossiers(frozen_path, cache, strict_corpus=True)
    receipt = {
        "schema_version": "jaa04.capture-receipt.v1", "status": "SUCCESS",
        "captured_count": len(dossiers),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "dossiers_sha256": hashlib.sha256(frozen_path.read_bytes()).hexdigest(),
        "raw_corpus_sha256": raw_corpus_hash(),
        "source_plan_contract": {
            "intelligence_kinds": ["company", "hiring", "operational_health", "product", "role"],
            "coverage": "one-plan-one-source-one-claim-per-kind",
            "byte_binding": "sha256-and-exact-byte-range",
        },
    }
    (CAPTURE / "capture_receipt.json").write_bytes(canonical(receipt))
    print("JAA-04 corpus rebuild: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
