#!/usr/bin/env python3
"""Rebuild reviewed JAA-04 dossiers from the receipt-backed captured bytes."""

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


def main() -> int:
    frozen_path = CAPTURE / "frozen_dossiers.json"
    manifest_path = CAPTURE / "research_manifest.json"
    receipt_path = CAPTURE / "capture_receipt.json"
    previous = json.loads(frozen_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache = RawResponseCache(CAPTURE / "raw")
    dossiers = []
    records = []
    for old, record in zip(previous["dossiers"], manifest["records"], strict=True):
        source = old["sources"][0]
        company = str(record["company"])
        role = str(record.get("role") or "Technology role")
        task = SimpleNamespace(job_key=old["job_key"], company=company, title=role)
        dossier = build_reconnaissance_dossier(task, Citation(**source), cache,
                                                observed_at=source["captured_at"])
        dossier["raw_cache_root"] = "raw"
        dossiers.append(dossier)
        row = dict(record)
        row.update({
            "company": company, "role": task.title,
            "intelligence_kinds": sorted({c["kind"] for c in dossier["claims"]}),
            "classifications": sorted({c["classification"] for c in dossier["claims"]}),
            "edge_relations": sorted({e["relation"] for e in dossier["edges"]}),
        })
        records.append(row)
    frozen_bytes = canonical({"schema_version": "jaa04.frozen-dossiers.v1",
                              "dossiers": dossiers, "dossiers_hash": content_hash(dossiers)})
    manifest_bytes = canonical({"schema_version": "jaa04.research-manifest.v2",
                                "records": records, "records_hash": content_hash(records)})
    frozen_path.write_bytes(frozen_bytes)
    manifest_path.write_bytes(manifest_bytes)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["dossiers_sha256"] = hashlib.sha256(frozen_bytes).hexdigest()
    receipt["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    receipt["substantive_intelligence"] = {
        "kinds": ["company", "hiring", "operational_health", "product", "role"],
        "classifications": ["fact", "hypothesis", "inference"],
        "typed_edge_relations": ["qualifies", "supports"],
        "excerpt_binding": "verbatim-utf8-subsequence-of-sha256-addressed-response",
    }
    receipt_path.write_bytes(canonical(receipt))
    load_frozen_dossiers(frozen_path, cache, strict_corpus=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
